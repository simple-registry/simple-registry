//! Maintenance of the OCI-1.0 referrers fallback tag on downstreams that do
//! not auto-index subjects: the push side merges a referrer's descriptor into
//! the subject's fallback index, the delete side prunes it, and both run their
//! GET/modify/PUT under one per-subject lock so concurrent jobs cannot drop
//! each other's update.

use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::time::timeout;
use tracing::warn;

use angos_oci::manifest_accept_types;
use angos_oci::request::{DeleteManifestRequest, GetManifestRequest, PutManifestRequest};
use angos_oci::{Content, Descriptor, Digest, Manifest, MediaType, Namespace, Reference, Tag};

use crate::{
    registry::{ParsedManifestDigests, metadata_store::MetadataStore, parse_manifest_digests},
    registry_client::{Error as ClientError, RegistryClient},
    replication::Error,
};

/// Upper bound on each downstream HTTP call inside the referrers-merge
/// critical section, kept well below the metadata executor lock's 300-second
/// max-hold lease (the tx-engine default) so a hung downstream cannot outlive
/// the lease and let a concurrent merge re-admit a lost update.
const REFERRERS_MERGE_HTTP_TIMEOUT: Duration = Duration::from_mins(1);

/// Pushes the OCI-1.0 referrers fallback tag index for a subject-bearing
/// manifest the downstream did not auto-index.
///
/// The fallback tag (`<alg>-<hash>` of the subject digest) holds a merged image
/// index of referrer descriptors; its PUT is deliberately timestamp-less, since
/// a set merge must never lose an LWW comparison and drop a descriptor.
pub async fn push_referrers_fallback(
    downstream: &RegistryClient,
    metadata_store: &Arc<MetadataStore>,
    namespace: &Namespace,
    downstream_namespace: &Namespace,
    digest: &Digest,
    parsed: &ParsedManifestDigests,
    body: &[u8],
) -> Result<(), Error> {
    let Some(subject) = &parsed.subject else {
        return Ok(());
    };
    let fallback_tag = Tag::referrers_fallback(subject);
    let reference = Reference::Tag(fallback_tag.clone());
    warn!(
        namespace = %namespace,
        %digest,
        %subject,
        %fallback_tag,
        "Downstream did not index subject (OCI-1.0); merging referrers fallback index"
    );
    with_subject_lock(
        metadata_store,
        namespace,
        subject,
        &fallback_tag,
        async || {
            merge_referrers_fallback(
                downstream,
                downstream_namespace,
                &reference,
                digest,
                parsed,
                body,
            )
            .await
        },
    )
    .await
}

/// Drops `referrer`'s descriptor from the subject's OCI-1.0 referrers fallback
/// index, deleting the fallback tag when no referrers remain. Serialized under
/// the same per-subject lock as the push-side merge, so a concurrent add and
/// this removal cannot lose each other's update.
pub async fn remove_referrers_fallback(
    downstream: &RegistryClient,
    metadata_store: &Arc<MetadataStore>,
    namespace: &Namespace,
    downstream_namespace: &Namespace,
    subject: &Digest,
    referrer: &Digest,
) -> Result<(), Error> {
    let fallback_tag = Tag::referrers_fallback(subject);
    let reference = Reference::Tag(fallback_tag.clone());
    with_subject_lock(
        metadata_store,
        namespace,
        subject,
        &fallback_tag,
        async || {
            prune_fallback_descriptor(downstream, downstream_namespace, &reference, referrer).await
        },
    )
    .await
}

/// GETs the manifest at `digest` from the downstream and returns its subject
/// when it is a referrer. Best-effort: any failure (absent, unparseable, or no
/// subject) yields `None`, leaving the fallback index untouched.
pub async fn deleted_referrer_subject(
    downstream: &RegistryClient,
    downstream_namespace: &Namespace,
    digest: &Digest,
) -> Option<Digest> {
    let fetched = downstream
        .get_manifest(GetManifestRequest {
            namespace: downstream_namespace.clone(),
            reference: Reference::Digest(digest.clone()),
            accepted_types: manifest_accept_types(),
            allow_redirect: true,
        })
        .await
        .ok()?;
    parse_manifest_digests(&fetched.body, None).ok()?.subject
}

/// Runs `critical` (the GET/modify/PUT of one fallback index) under the
/// subject's merge lock: two referrers of the same subject are distinct jobs
/// the queue runs concurrently, and unserialized merges read the same base
/// index and drop the loser's descriptor. The lock lives on the metadata
/// executor, which every drain of this store shares, but cannot cover an
/// unrelated sender registry pushing to the same downstream.
///
/// The key is deliberately downstream-agnostic: the critical section is two
/// short HTTP calls, so cross-downstream contention never matters in practice.
async fn with_subject_lock(
    metadata_store: &Arc<MetadataStore>,
    namespace: &Namespace,
    subject: &Digest,
    fallback_tag: &str,
    critical: impl AsyncFnOnce() -> Result<(), Error>,
) -> Result<(), Error> {
    let lock_keys = [format!("replication-referrers:{namespace}:{subject}")];
    let session = metadata_store
        .store()
        .acquire(&lock_keys)
        .await
        .map_err(|e| {
            Error::Internal(format!(
                "referrers fallback lock acquire failed for '{fallback_tag}': {e}"
            ))
        })?;
    let result = critical().await;
    session.release().await;
    result
}

/// The locked critical section of [`push_referrers_fallback`]: fetches the
/// downstream's current fallback index, appends this referrer's descriptor when
/// absent, and PUTs the merged index back.
async fn merge_referrers_fallback(
    downstream: &RegistryClient,
    namespace: &Namespace,
    reference: &Reference,
    digest: &Digest,
    parsed: &ParsedManifestDigests,
    body: &[u8],
) -> Result<(), Error> {
    let mut manifests = fetch_fallback_manifests(downstream, namespace, reference).await?;

    // Dedup by digest so a re-run is idempotent. The blob store is
    // content-addressed, so `digest` is already the body's digest.
    if !manifests.iter().any(|entry| entry.digest == *digest) {
        manifests.push(referrer_descriptor(digest, body.len(), parsed));
    }

    put_fallback_manifests(downstream, namespace, reference, manifests).await
}

/// Locked critical section of [`remove_referrers_fallback`]: GET the index, drop
/// the descriptor, then PUT the remainder back, or DELETE the tag when empty.
async fn prune_fallback_descriptor(
    downstream: &RegistryClient,
    namespace: &Namespace,
    reference: &Reference,
    referrer: &Digest,
) -> Result<(), Error> {
    let mut manifests = fetch_fallback_manifests(downstream, namespace, reference).await?;

    let before = manifests.len();
    manifests.retain(|entry| entry.digest != *referrer);
    // Descriptor absent (already pruned, or a 1.1 downstream has no fallback tag
    // and the GET returned an empty base): nothing to do.
    if manifests.len() == before {
        return Ok(());
    }

    if manifests.is_empty() {
        // No referrers remain: drop the fallback tag rather than leave an empty
        // index. Timestamp-less, mirroring the merge PUT.
        timeout(
            REFERRERS_MERGE_HTTP_TIMEOUT,
            downstream.delete_manifest(DeleteManifestRequest {
                namespace: namespace.clone(),
                reference: reference.clone(),
                source_ts: None,
            }),
        )
        .await
        .map_err(|_| {
            Error::Internal(format!(
                "referrers fallback DELETE of '{namespace}/{reference}' timed out inside the \
                 merge lock"
            ))
        })??;
        return Ok(());
    }

    put_fallback_manifests(downstream, namespace, reference, manifests).await
}

/// GETs the existing referrers fallback index at `location`, bounded by the
/// merge-lock HTTP timeout, and returns its `manifests[]` descriptors.
///
/// Only a `404` yields an empty base; any other error, including a `200` body
/// that is not a parseable image index, propagates so the caller never rebuilds
/// the index from an empty base and drops the subject's sibling referrers.
async fn fetch_fallback_manifests(
    downstream: &RegistryClient,
    namespace: &Namespace,
    reference: &Reference,
) -> Result<Vec<Descriptor>, Error> {
    let accept = manifest_accept_types();
    let get = downstream.get_manifest(GetManifestRequest {
        namespace: namespace.clone(),
        reference: reference.clone(),
        accepted_types: accept,
        allow_redirect: true,
    });
    let body = match timeout(REFERRERS_MERGE_HTTP_TIMEOUT, get).await {
        Ok(Ok(fetched)) => fetched.body,
        Ok(Err(ClientError::ManifestUnknown)) => return Ok(Vec::new()),
        Ok(Err(e)) => return Err(Error::Client(e)),
        Err(_) => {
            return Err(Error::Internal(format!(
                "referrers fallback GET of '{namespace}/{reference}' timed out inside the merge \
                 lock"
            )));
        }
    };
    match Manifest::from_slice(&body).map(|index| index.content) {
        Ok(Content::Index { manifests }) => Ok(manifests),
        _ => Err(Error::Internal(format!(
            "downstream referrers fallback index at '{namespace}/{reference}' is not a parseable \
             image index; refusing to overwrite it"
        ))),
    }
}

/// Serializes `manifests` into an image index and PUTs it to `location`.
///
/// Timestamp-less: the receiver then skips LWW, so the merged index can never
/// come back superseded and silently drop a descriptor. Bounded by the
/// merge-lock HTTP timeout.
async fn put_fallback_manifests(
    downstream: &RegistryClient,
    namespace: &Namespace,
    reference: &Reference,
    manifests: Vec<Descriptor>,
) -> Result<(), Error> {
    let index_body = serde_json::to_vec(&Manifest::oci_index(manifests)).map_err(|e| {
        Error::Internal(format!("failed to serialize referrers fallback index: {e}"))
    })?;
    timeout(
        REFERRERS_MERGE_HTTP_TIMEOUT,
        downstream.put_manifest(
            PutManifestRequest {
                namespace: namespace.clone(),
                reference: reference.clone(),
                content_type: Some(MediaType::oci_index()),
                tags: Vec::new(),
                source_ts: None,
            },
            index_body,
        ),
    )
    .await
    .map_err(|_| {
        Error::Internal(format!(
            "referrers fallback PUT of '{namespace}/{reference}' timed out inside the merge lock"
        ))
    })??;
    Ok(())
}

/// The descriptor a referrer is listed under in the fallback index. A body that
/// declared no `mediaType` is described as an OCI image manifest, which is what
/// the referrers API says an entry without one is.
fn referrer_descriptor(digest: &Digest, size: usize, parsed: &ParsedManifestDigests) -> Descriptor {
    Descriptor {
        media_type: parsed
            .media_type
            .clone()
            .unwrap_or_else(MediaType::oci_manifest),
        digest: digest.clone(),
        size: size as u64,
        annotations: HashMap::new(),
        artifact_type: parsed.artifact_type.clone(),
        platform: None,
    }
}
