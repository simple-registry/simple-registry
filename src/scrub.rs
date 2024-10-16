use crate::error::RegistryError;
use crate::oci::Digest;
use crate::registry::{parse_manifest_digests, LinkReference, Registry};
use crate::REGISTRY;
use arc_swap::Guard;
use chrono::{Duration, Utc};
use std::io;
use std::process::exit;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

async fn ensure_link(
    registry: &Registry,
    namespace: &str,
    link_reference: &LinkReference,
    digest: &Digest,
    auto_fix: bool,
) -> Result<(), RegistryError> {
    let blob_digest = registry
        .storage
        .read_link(namespace, link_reference)
        .await
        .ok();

    if blob_digest != Some(digest.clone()) {
        warn!(
            "Invalid revision: expected '{:?}', found '{:?}'",
            digest, blob_digest
        );
        if auto_fix {
            registry
                .storage
                .create_link(namespace, link_reference, digest)
                .await?;
        }
    }
    Ok(())
}

pub async fn scrub(auto_fix: bool) -> io::Result<()> {
    if !auto_fix {
        info!("Dry-run mode: no changes will be made to the storage");
    }

    let registry = REGISTRY.load();
    // TODO: allow to run only selected steps (e.g. --uploads, --tags, --revisions, --blobs)

    // Step 1: check upload directories
    // - for incomplete uploads (threshold from config file)
    // - delete corrupted upload directories (here we are incompatible with docker "distribution")
    cleanup_uploads(&registry, Duration::hours(24), auto_fix).await; // TODO: customizable threshold

    // Step 2: for each manifest tags "_manifests/tags/<tag-name>/current/link", ensure the
    // revision exists: "_manifests/revisions/sha256/<hash>/link"
    ensure_tags_have_revision(&registry, auto_fix).await;

    // Step 3: for each revision "_manifests/revisions/sha256/<hash>/link", read the manifest,
    // and ensure related links exists
    ensure_revisions_are_coherent(&registry, auto_fix).await;

    // Step 4: blob garbage collection
    cleanup_orphan_blobs(&registry, auto_fix).await;

    Ok(())
}

async fn cleanup_uploads(registry: &Guard<Arc<Registry>>, max_age: Duration, auto_fix: bool) {
    info!("Checking for obsolete uploads");
    let Ok(namespaces) = registry.storage.list_namespaces().await else {
        error!("Failed to read catalog");
        exit(1);
    };

    for namespace in namespaces {
        debug!("Checking namespace {} for obsolete uploads", namespace);
        let Ok(uploads) = registry.storage.list_uploads(&namespace).await else {
            error!("Failed to list uploads for namespace '{}'", namespace);
            continue;
        };

        for (uuid, hash, start_date) in uploads {
            if hash.is_none() {
                warn!(
                    "Unreadable hash state for upload '{}' of namespace '{}'",
                    uuid, namespace
                );
                if auto_fix {
                    if let Err(err) = registry.storage.delete_upload(&namespace, &uuid).await {
                        error!("Failed to delete upload '{}': {}", uuid, err);
                    }
                }
                continue;
            }

            match start_date {
                Some(start_date) => {
                    let now = Utc::now();
                    let duration = now.signed_duration_since(start_date);
                    if duration > max_age {
                        warn!(
                            "Upload '{}' of namespace '{}' was not completed in time",
                            uuid, namespace
                        );
                        if auto_fix {
                            if let Err(err) =
                                registry.storage.delete_upload(&namespace, &uuid).await
                            {
                                error!("Failed to delete upload '{}': {}", uuid, err);
                            }
                        }
                    }
                }
                None => {
                    warn!(
                        "Upload '{}' of namespace '{}' invalid start date",
                        uuid, namespace
                    );
                    if auto_fix {
                        if let Err(err) = registry.storage.delete_upload(&namespace, &uuid).await {
                            error!("Failed to delete upload '{}': {}", uuid, err);
                        }
                    }
                }
            }
        }
    }
}

async fn ensure_tags_have_revision(registry: &Registry, auto_fix: bool) {
    info!("Checking tags & revision inconsistencies");
    let Ok(namespaces) = registry.storage.list_namespaces().await else {
        error!("Failed to read catalog");
        exit(1);
    };

    for namespace in namespaces {
        debug!(
            "Checking namespace {} for tag to revision inconsistencies",
            namespace
        );
        let Ok(tags) = registry.storage.list_tags(&namespace).await else {
            error!("Failed to list tags for namespace '{}'", namespace);
            continue;
        };

        for tag in tags {
            check_tag_revision(registry, &namespace, &tag, auto_fix).await;
        }
    }
}

async fn ensure_revisions_are_coherent(registry: &Registry, auto_fix: bool) {
    info!("Checking revisions & other links consistency");
    let Ok(namespaces) = registry.storage.list_namespaces().await else {
        error!("Failed to read catalog");
        exit(1);
    };

    for namespace in namespaces {
        debug!(
            "Checking namespace {} for tag to revision inconsistencies",
            namespace
        );
        if let Ok(revisions) = registry.storage.list_revisions(&namespace).await {
            for revision in revisions {
                let Ok(content) = registry.storage.read_blob(&revision).await else {
                    error!("Failed to read revision: {}@{}", namespace, revision);
                    continue;
                };

                let Ok(manifest_digests) = parse_manifest_digests(&content, None) else {
                    error!("Failed to parse manifest: {}@{}", namespace, revision);
                    continue;
                };

                check_manifest_layers(
                    registry,
                    &namespace,
                    &revision,
                    &manifest_digests.layers,
                    auto_fix,
                )
                .await;
                check_manifest_config(
                    registry,
                    &namespace,
                    &revision,
                    manifest_digests.config,
                    auto_fix,
                )
                .await;
                check_manifest_subject(
                    registry,
                    &namespace,
                    &revision,
                    manifest_digests.subject,
                    auto_fix,
                )
                .await;
            }
        }
    }
}

async fn cleanup_orphan_blobs(registry: &Registry, auto_fix: bool) {
    info!("Checking for orphan blobs");
    let Ok(blobs) = registry.storage.list_blobs().await else {
        error!("Failed to list blobs");
        exit(1);
    };

    for blog_digest in blobs {
        let Ok(mut blob_index) = registry.storage.read_blob_index(&blog_digest).await else {
            error!("Failed to read blob index: {}", blog_digest);
            continue;
        };

        for (namespace, references) in blob_index.namespace.clone() {
            for link_reference in references {
                if registry
                    .storage
                    .read_link(&namespace, &link_reference)
                    .await
                    .is_err()
                {
                    let Some(index) = blob_index.namespace.get_mut(&namespace) else {
                        error!("Failed to get namespace index: {}", namespace);
                        continue;
                    };

                    warn!(
                        "Orphan link: {}@{} -> {:?}",
                        namespace, blog_digest, link_reference
                    );
                    if auto_fix {
                        index.remove(&link_reference);
                    }
                }
            }
        }

        blob_index
            .namespace
            .retain(|_, references| !references.is_empty());

        if blob_index.namespace.is_empty() {
            warn!("Orphan blob: {}", blog_digest);
            if auto_fix {
                if let Err(e) = registry.storage.delete_blob( & blog_digest).await {
                    error!("Failed to delete blob: {}",
                    e);
                }
            }
        }
    }
}

async fn check_tag_revision(registry: &Registry, namespace: &str, tag: &str, auto_fix: bool) {
    debug!(
        "Checking {}:{} for revision inconsistencies",
        namespace, tag
    );

    let Ok(digest) = registry
        .storage
        .read_link(namespace, &LinkReference::Tag(tag.to_string()))
        .await
    else {
        error!("Failed to read link for tag: {}", tag);
        return;
    };

    let link_reference = LinkReference::Digest(digest.clone());
    if let Err(e) = ensure_link(registry, namespace, &link_reference, &digest, auto_fix).await {
        warn!("Failed to ensure link: {}", e);
    }
}

async fn check_manifest_config(
    registry: &Registry,
    namespace: &str,
    revision: &Digest,
    config_digest: Option<Digest>,
    auto_fix: bool,
) {
    let Some(config_digest) = config_digest else {
        return;
    };

    debug!(
        "Checking {}@{} config link: {}",
        namespace, revision, config_digest
    );

    let link_reference = LinkReference::Config(config_digest.clone());
    if let Err(e) = ensure_link(
        registry,
        namespace,
        &link_reference,
        &config_digest,
        auto_fix,
    )
    .await
    {
        warn!("Failed to ensure link: {}", e);
    }
}

async fn check_manifest_subject(
    registry: &Registry,
    namespace: &str,
    revision: &Digest,
    subject_digest: Option<Digest>,
    auto_fix: bool,
) {
    let Some(subject_digest) = subject_digest else {
        return;
    };

    debug!(
        "Checking {}@{} subject link: {}",
        namespace, revision, subject_digest
    );
    let link_reference = LinkReference::Referrer(subject_digest.clone(), revision.clone());
    if let Err(e) = ensure_link(registry, namespace, &link_reference, revision, auto_fix).await {
        warn!("Failed to ensure link: {}", e);
    }
}

async fn check_manifest_layers(
    registry: &Registry,
    namespace: &str,
    revision: &Digest,
    layers: &Vec<Digest>,
    auto_fix: bool,
) {
    for layer_digest in layers {
        debug!(
            "Checking {}@{} layer link: {}",
            namespace, revision, layer_digest
        );

        let link_reference = LinkReference::Layer(layer_digest.clone());
        if let Err(e) =
            ensure_link(registry, namespace, &link_reference, layer_digest, auto_fix).await
        {
            warn!("Failed to ensure link: {}", e);
        }
    }
}
