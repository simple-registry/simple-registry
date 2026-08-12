use futures_util::stream::TryStreamExt;
use hyper::{
    HeaderMap, Response, StatusCode,
    header::{CONTENT_TYPE, HeaderValue, LINK},
};
use serde::Serialize;
use tracing::{instrument, warn};

use crate::{
    http_response::{ResponseBody, build_response, json_headers},
    oci::{
        Descriptor, Digest, Manifest, MediaType, Namespace, OCI_INDEX_MEDIA_TYPE,
        OCI_MANIFEST_SCHEMA_VERSION, Tag,
    },
    registry::{Error, OCI_FILTERS_APPLIED, Registry, metadata_store::LinkKind},
};

pub struct ListCatalogRequest {
    pub n: Option<u16>,
    pub last: Option<String>,
}

pub struct ListTagsRequest {
    pub namespace: Namespace,
    pub n: Option<u16>,
    pub last: Option<String>,
}

#[derive(Serialize)]
pub struct CatalogBody {
    pub repositories: Vec<Namespace>,
}

#[derive(Serialize)]
pub struct TagsBody {
    pub name: Namespace,
    pub tags: Vec<Tag>,
}

fn paginated_json_headers(link: Option<&str>) -> Result<HeaderMap, Error> {
    let mut headers = json_headers();
    if let Some(link) = link {
        headers.insert(
            LINK,
            HeaderValue::try_from(format!("<{link}>; rel=\"next\""))?,
        );
    }

    Ok(headers)
}

pub struct GetReferrersRequest {
    pub namespace: Namespace,
    pub digest: Digest,
    pub artifact_type: Option<MediaType>,
}

/// The OCI image-index body a referrers listing serves.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ReferrerList {
    schema_version: i32,
    // The OCI index media type serializes as its string, so the constant is
    // carried directly rather than re-parsed through the fallible `MediaType`.
    media_type: &'static str,
    manifests: Vec<Descriptor>,
}

/// A listing that honoured an `artifactType` filter must advertise it, so a
/// client can tell a filtered index from a complete one.
fn referrers_headers(artifact_type_filtered: bool) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::try_from(OCI_INDEX_MEDIA_TYPE)?);
    if artifact_type_filtered {
        headers.insert(
            OCI_FILTERS_APPLIED,
            HeaderValue::from_static("artifactType"),
        );
    }

    Ok(headers)
}

/// Fan-out for resolving referrer candidates to descriptors: each candidate is
/// an independent manifest read, so a bounded window keeps the listing and the
/// reads overlapped.
const REFERRER_RESOLVE_CONCURRENCY: usize = 10;

/// Default page size applied when a listing request omits `n`. Shared with the
/// HTTP handlers so the pagination `Link` they build echoes the size actually
/// used.
pub const DEFAULT_PAGE_SIZE: u16 = 100;

impl Registry {
    /// Lists namespaces, one page at a time, advertising the next page through
    /// the `Link` header when the listing is not exhausted.
    pub async fn list_catalog_entries(
        &self,
        request: ListCatalogRequest,
    ) -> Result<Response<ResponseBody>, Error> {
        let n = request.n.unwrap_or(DEFAULT_PAGE_SIZE);
        let page = self.metadata_store.list_namespaces(n, request.last).await?;
        let link = page
            .next_token
            .as_ref()
            .map(|last| format!("/v2/_catalog?n={n}&last={last}"));

        let body = CatalogBody {
            repositories: page.items,
        };

        Ok(build_response(
            StatusCode::OK,
            paginated_json_headers(link.as_deref())?,
            ResponseBody::fixed(serde_json::to_vec(&body)?),
        )?)
    }

    /// Lists a namespace's tags, one page at a time, advertising the next page
    /// through the `Link` header when the listing is not exhausted.
    pub async fn list_tag_entries(
        &self,
        request: ListTagsRequest,
    ) -> Result<Response<ResponseBody>, Error> {
        let n = request.n.unwrap_or(DEFAULT_PAGE_SIZE);
        let page = self
            .metadata_store
            .list_tags(&request.namespace, n, request.last)
            .await?;
        let namespace = &request.namespace;
        let link = page
            .next_token
            .as_ref()
            .map(|last| format!("/v2/{namespace}/tags/list?n={n}&last={last}"));

        let body = TagsBody {
            name: request.namespace.clone(),
            tags: page.items,
        };

        Ok(build_response(
            StatusCode::OK,
            paginated_json_headers(link.as_deref())?,
            ResponseBody::fixed(serde_json::to_vec(&body)?),
        )?)
    }

    /// Resolves a subject's referrers into the OCI image index that serves them.
    #[instrument(skip(request))]
    pub async fn get_referrers(
        &self,
        request: GetReferrersRequest,
    ) -> Result<Response<ResponseBody>, Error> {
        let filter_applied = request.artifact_type.is_some();
        let manifests = self
            .list_referrers(&request.namespace, &request.digest, request.artifact_type)
            .await?;

        let body = ReferrerList {
            schema_version: OCI_MANIFEST_SCHEMA_VERSION,
            media_type: OCI_INDEX_MEDIA_TYPE,
            manifests,
        };

        Ok(build_response(
            StatusCode::OK,
            referrers_headers(filter_applied)?,
            ResponseBody::fixed(serde_json::to_vec(&body)?),
        )?)
    }

    /// Resolves every referrer of `digest` in `namespace` to a sorted
    /// descriptor list, filtered by `artifact_type` when given.
    #[instrument]
    pub async fn list_referrers(
        &self,
        namespace: &Namespace,
        digest: &Digest,
        artifact_type: Option<MediaType>,
    ) -> Result<Vec<Descriptor>, Error> {
        let artifact_type = artifact_type.as_ref();

        // Candidate digests stream off the listing while up to
        // `REFERRER_RESOLVE_CONCURRENCY` of them resolve concurrently, so the
        // resolution window spans page boundaries and overlaps the page fetches.
        let mut referrers: Vec<Descriptor> = self
            .metadata_store
            .stream_referrer_digests(namespace, digest)
            .map_ok(|manifest_digest| async move {
                Ok::<_, Error>(
                    self.resolve_referrer_descriptor(
                        namespace,
                        digest,
                        manifest_digest,
                        artifact_type,
                    )
                    .await,
                )
            })
            .try_buffer_unordered(REFERRER_RESOLVE_CONCURRENCY)
            .try_filter_map(|descriptor| async move { Ok(descriptor) })
            .try_collect()
            .await?;

        referrers.sort_by(|a, b| a.digest.cmp(&b.digest));
        Ok(referrers)
    }

    /// Resolves a single referrer entry to an OCI [`Descriptor`], applying an
    /// optional `artifact_type` filter: returns the cached link descriptor
    /// when that suffices, else falls back to reading the manifest through the
    /// blob store, where manifest bodies live.
    async fn resolve_referrer_descriptor(
        &self,
        namespace: &Namespace,
        subject_digest: &Digest,
        manifest_digest: Digest,
        artifact_type: Option<&MediaType>,
    ) -> Option<Descriptor> {
        let referrer_link = LinkKind::Referrer {
            subject: subject_digest.clone(),
            referrer: manifest_digest.clone(),
        };

        if let Ok(metadata) = self
            .metadata_store
            .read_link_reference(namespace, &referrer_link)
            .await
            && let Some(desc) = metadata.descriptor
        {
            match artifact_type {
                Some(at) if desc.artifact_type.as_ref() == Some(at) => {
                    return Some(desc);
                }
                None => return Some(desc),
                // Cached descriptor has no artifact_type; fall through to manifest
                // read so the filter can be evaluated against the full manifest data.
                Some(_) if desc.artifact_type.is_none() => {}
                Some(_) => return None,
            }
        }

        match self.blob_store.read(&manifest_digest).await {
            Ok(data) => {
                let manifest_len = data.len();
                match Manifest::from_slice(&data) {
                    Ok(mut manifest) => {
                        if !manifest.artifact_type_matches(artifact_type) {
                            return None;
                        }
                        manifest.take_descriptor(manifest_digest, manifest_len as u64)
                    }
                    Err(e) => {
                        warn!("Failed to parse referrer manifest {manifest_digest}: {e}");
                        None
                    }
                }
            }
            Err(Error::BlobUnknown) => {
                warn!("Referrer manifest blob {manifest_digest} not found, skipping");
                None
            }
            Err(e) => {
                warn!("Failed to read referrer manifest {manifest_digest}: {e}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hyper::header::LINK;

    use super::{ListCatalogRequest, ListTagsRequest, Response, ResponseBody};

    /// The `last` cursor a client would follow out of a `Link` header, or
    /// `None` once the listing is exhausted and no `Link` is advertised.
    /// The repository names a catalog response served.
    async fn catalog(response: Response<ResponseBody>) -> Vec<String> {
        json_strings(response, "repositories").await
    }

    /// The tag names a tags response served.
    async fn tags(response: Response<ResponseBody>) -> Vec<String> {
        json_strings(response, "tags").await
    }

    async fn json_strings(response: Response<ResponseBody>, field: &str) -> Vec<String> {
        response_json(response).await[field]
            .as_array()
            .expect("the listing field must be an array")
            .iter()
            .map(|value| value.as_str().expect("entries are strings").to_string())
            .collect()
    }

    fn next_cursor(response: &Response<ResponseBody>) -> Option<String> {
        let link = response.headers().get(LINK)?.to_str().ok()?;
        let (_, last) = link.rsplit_once("last=")?;
        Some(last.trim_end_matches(">; rel=\"next\"").to_string())
    }
    use crate::{
        oci::{Descriptor, Digest, Manifest, MediaType, Namespace, Reference, Tag},
        registry::{
            metadata_store::{LinkKind, LinkOperation, MetadataStore},
            test_utils::{
                FSRegistryTestCase, create_test_blob, for_each_backend, media_type,
                put_blob_direct, response_json, upload_blob,
            },
        },
    };

    #[tokio::test]
    async fn test_list_catalog_entries() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();

            for request in [
                ListCatalogRequest {
                    n: None,
                    last: None,
                },
                ListCatalogRequest {
                    n: Some(10),
                    last: None,
                },
                ListCatalogRequest {
                    n: Some(10),
                    last: Some("test".to_string()),
                },
            ] {
                let response = registry.list_catalog_entries(request).await.unwrap();
                assert!(next_cursor(&response).is_none());
                assert!(catalog(response).await.is_empty());
            }
        })
        .await;
    }

    #[tokio::test]
    async fn test_list_tag_entries() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = Namespace::new("test-repo").unwrap();

            let test_content = b"test content";
            let test_digest = put_blob_direct(registry.metadata_store.store(), test_content).await;
            let ops: Vec<LinkOperation> = ["latest", "v1.0", "v2.0"]
                .iter()
                .map(|&tag| {
                    LinkOperation::create(
                        LinkKind::Tag(Tag::new(tag).unwrap()),
                        test_digest.clone(),
                    )
                })
                .collect();
            registry
                .metadata_store
                .update_links(&namespace, &ops)
                .await
                .unwrap();

            let list = async |n: Option<u16>, last: Option<String>| {
                registry
                    .list_tag_entries(ListTagsRequest {
                        namespace: namespace.clone(),
                        n,
                        last,
                    })
                    .await
                    .unwrap()
            };

            let all = list(None, None).await;
            assert!(next_cursor(&all).is_none());
            let body = response_json(all).await;
            assert_eq!(body["name"], namespace.as_ref());
            assert_eq!(
                body["tags"].as_array().unwrap().len(),
                3,
                "every tag must be listed"
            );

            let page1 = list(Some(2), None).await;
            let cursor = next_cursor(&page1).expect("a partial page must advertise Link");
            assert_eq!(tags(page1).await.len(), 2);

            let page2 = list(Some(2), Some(cursor)).await;
            assert!(next_cursor(&page2).is_none());
            assert_eq!(tags(page2).await.len(), 1);

            let one = list(Some(1), None).await;
            let cursor = next_cursor(&one).expect("a partial page must advertise Link");
            assert_eq!(tags(one).await.len(), 1);

            let two = list(Some(1), Some(cursor)).await;
            let cursor = next_cursor(&two).expect("a partial page must advertise Link");
            assert_eq!(tags(two).await.len(), 1);

            let three = list(Some(1), Some(cursor)).await;
            assert!(next_cursor(&three).is_none());
            assert_eq!(tags(three).await.len(), 1);

            let after_latest = list(Some(10), Some("latest".to_string())).await;
            assert!(next_cursor(&after_latest).is_none());
            assert_eq!(tags(after_latest).await.len(), 2);
        })
        .await;
    }

    // list_catalog_entries pagination: write N namespaces then page through them
    // using the returned continuation token, asserting every entry is visited
    // exactly once.
    #[tokio::test]
    async fn list_catalog_entries_continuation_token_round_trip() {
        // Use only the FS backend: this tests pagination logic, not backend specifics.
        let test_case = crate::registry::test_utils::FSRegistryTestCase::new();
        let registry = test_case.registry();

        let namespaces = [
            "alpha/image",
            "beta/image",
            "gamma/image",
            "delta/image",
            "epsilon/image",
        ];

        let blob_content = b"pagination-test-blob";
        let digest = put_blob_direct(registry.metadata_store.store(), blob_content).await;

        for ns_str in &namespaces {
            let ns = Namespace::new(ns_str).unwrap();
            registry
                .metadata_store
                .update_links(
                    &ns,
                    &[LinkOperation::create(
                        LinkKind::Tag(Tag::new("latest").unwrap()),
                        digest.clone(),
                    )],
                )
                .await
                .unwrap();
        }

        // Fetch 2 at a time and collect all namespaces.
        let mut all_collected: Vec<String> = Vec::new();
        let mut last: Option<String> = None;

        loop {
            let response = registry
                .list_catalog_entries(ListCatalogRequest { n: Some(2), last })
                .await
                .unwrap();
            let cursor = next_cursor(&response);
            all_collected.extend(catalog(response).await);

            // Follow the advertised `Link` exactly as a paging client would.
            match cursor {
                None => break,
                Some(cursor) => last = Some(cursor),
            }
        }

        assert_eq!(
            all_collected.len(),
            namespaces.len(),
            "pagination must visit every namespace exactly once"
        );
        for ns in &namespaces {
            assert!(
                all_collected.iter().any(|got| got == ns),
                "namespace '{ns}' must appear in paginated results"
            );
        }
    }

    // list_tag_entries for a namespace that has never been written must return
    // an empty tag list and no continuation token.
    #[tokio::test]
    async fn list_tag_entries_unknown_namespace_returns_empty() {
        let test_case = crate::registry::test_utils::FSRegistryTestCase::new();
        let registry = test_case.registry();

        let response = registry
            .list_tag_entries(ListTagsRequest {
                namespace: Namespace::new("no-such-repo/no-such-image").unwrap(),
                n: None,
                last: None,
            })
            .await
            .unwrap();

        assert!(
            next_cursor(&response).is_none(),
            "unknown namespace must have no continuation token"
        );
        assert!(
            tags(response).await.is_empty(),
            "unknown namespace must have no tags"
        );
    }

    #[tokio::test]
    async fn test_list_referrers_with_manifest() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();

            let manifest_content = r#"{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"}"#;
            let media_type =
                MediaType::new("application/vnd.docker.distribution.manifest.v2+json").unwrap();

            let (base_manifest_digest, _) =
                create_test_blob(registry, namespace, manifest_content.as_bytes()).await;
            registry
                .put_manifest(
                    namespace,
                    &Reference::Digest(base_manifest_digest.clone()),
                    Some(&media_type),
                    manifest_content.as_bytes(),
                )
                .await
                .unwrap();

            let (referrer_manifest_digest, _) =
                create_test_blob(registry, namespace, manifest_content.as_bytes()).await;
            registry
                .put_manifest(
                    namespace,
                    &Reference::Digest(referrer_manifest_digest.clone()),
                    Some(&media_type),
                    manifest_content.as_bytes(),
                )
                .await
                .unwrap();

            let referrer_link = LinkKind::Referrer { subject: base_manifest_digest.clone(), referrer: referrer_manifest_digest.clone(), };
            registry
                .metadata_store
                .update_links(
                    namespace,
                    &[LinkOperation::create(
                        referrer_link,
                        referrer_manifest_digest.clone(),
                    )],
                )
                .await
                .unwrap();

            let referrers = registry
                .list_referrers(namespace, &base_manifest_digest, None)
                .await
                .unwrap();

            assert_eq!(referrers.len(), 1);
            assert_eq!(referrers[0].digest, referrer_manifest_digest);
        })
        .await;
    }

    // The referrer-resolution tests below run on the split-backend fixture:
    // manifest bodies live in the blob store only, so any resolution path
    // reading them through the metadata store fails here.

    // A 64-char lowercase hex string for a digest with no stored blob.
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn subject() -> Digest {
        Digest::sha256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()
    }

    fn referrer_namespace() -> Namespace {
        Namespace::new("test-repo").unwrap()
    }

    fn descriptor_with(artifact_type: Option<&str>, manifest_digest: &Digest) -> Descriptor {
        Descriptor {
            media_type: media_type("application/vnd.oci.image.manifest.v1+json"),
            digest: manifest_digest.clone(),
            size: 100,
            annotations: HashMap::new(),
            artifact_type: artifact_type.map(media_type),
            platform: None,
        }
    }

    fn manifest_bytes(artifact_type: Option<&str>) -> Vec<u8> {
        let manifest = Manifest {
            schema_version: 2,
            media_type: Some(media_type("application/vnd.oci.image.manifest.v1+json")),
            artifact_type: artifact_type.map(media_type),
            ..Manifest::default()
        };
        serde_json::to_vec(&manifest).expect("serialization must succeed")
    }

    /// Split-backend registry fixture plus one referrer manifest uploaded
    /// through the blob store; the returned digest addresses that blob.
    async fn split_case_with_blob(
        blob_artifact_type: Option<&str>,
    ) -> (FSRegistryTestCase, Digest) {
        let case = FSRegistryTestCase::with_split_backends();
        let digest = upload_blob(
            case.registry(),
            &referrer_namespace(),
            &manifest_bytes(blob_artifact_type),
        )
        .await;
        (case, digest)
    }

    /// Creates the referrer link `subject() -> manifest`, optionally carrying
    /// a cached descriptor.
    async fn create_referrer_link(
        m: &MetadataStore,
        manifest: &Digest,
        descriptor: Option<Descriptor>,
    ) {
        let ops = vec![LinkOperation::Create {
            link: LinkKind::Referrer {
                subject: subject(),
                referrer: manifest.clone(),
            },
            target: manifest.clone(),
            referrer: None,
            media_type: None,
            descriptor: descriptor.map(Box::new),
        }];
        m.update_links(&referrer_namespace(), &ops).await.unwrap();
    }

    #[tokio::test]
    async fn returns_cached_descriptor_when_no_filter() {
        // The blob is deliberately unparseable: the cached descriptor must
        // answer without any manifest read.
        let case = FSRegistryTestCase::with_split_backends();
        let registry = case.registry();
        let manifest_digest = upload_blob(registry, &referrer_namespace(), b"not json").await;
        let desc = descriptor_with(Some("application/vnd.foo"), &manifest_digest);
        create_referrer_link(
            &registry.metadata_store,
            &manifest_digest,
            Some(desc.clone()),
        )
        .await;

        let result = registry
            .resolve_referrer_descriptor(&referrer_namespace(), &subject(), manifest_digest, None)
            .await;
        assert_eq!(result, Some(desc));
    }

    #[tokio::test]
    async fn returns_cached_descriptor_when_filter_matches() {
        let case = FSRegistryTestCase::with_split_backends();
        let registry = case.registry();
        let manifest_digest = upload_blob(registry, &referrer_namespace(), b"not json").await;
        let at = media_type("application/vnd.foo");
        let desc = descriptor_with(Some(&at), &manifest_digest);
        create_referrer_link(
            &registry.metadata_store,
            &manifest_digest,
            Some(desc.clone()),
        )
        .await;

        let result = registry
            .resolve_referrer_descriptor(
                &referrer_namespace(),
                &subject(),
                manifest_digest,
                Some(&at),
            )
            .await;
        assert_eq!(result, Some(desc));
    }

    #[tokio::test]
    async fn returns_none_when_cached_descriptor_filter_mismatches() {
        // The stored manifest DOES match the filter: a wrong fall-through to
        // the blob would return Some, so this pins the cache-only decision.
        let (case, manifest_digest) = split_case_with_blob(Some("application/vnd.bar")).await;
        let registry = case.registry();
        let desc = descriptor_with(Some("application/vnd.foo"), &manifest_digest);
        create_referrer_link(&registry.metadata_store, &manifest_digest, Some(desc)).await;

        let filter = media_type("application/vnd.bar");
        let result = registry
            .resolve_referrer_descriptor(
                &referrer_namespace(),
                &subject(),
                manifest_digest,
                Some(&filter),
            )
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn falls_through_to_blob_when_cached_descriptor_missing_artifact_type() {
        // Cached descriptor has artifact_type = None; filter is Some(...).
        // The filter cannot be evaluated from the cache entry alone, so the
        // manifest blob decides.
        let (case, manifest_digest) = split_case_with_blob(Some("application/vnd.foo")).await;
        let registry = case.registry();
        let desc = descriptor_with(None, &manifest_digest);
        create_referrer_link(&registry.metadata_store, &manifest_digest, Some(desc)).await;

        let at = media_type("application/vnd.foo");
        let result = registry
            .resolve_referrer_descriptor(
                &referrer_namespace(),
                &subject(),
                manifest_digest,
                Some(&at),
            )
            .await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn falls_through_to_blob_when_link_is_absent() {
        let (case, manifest_digest) = split_case_with_blob(None).await;
        let registry = case.registry();

        let result = registry
            .resolve_referrer_descriptor(&referrer_namespace(), &subject(), manifest_digest, None)
            .await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn falls_through_to_blob_when_link_carries_no_descriptor() {
        let (case, manifest_digest) = split_case_with_blob(None).await;
        let registry = case.registry();
        create_referrer_link(&registry.metadata_store, &manifest_digest, None).await;

        let result = registry
            .resolve_referrer_descriptor(&referrer_namespace(), &subject(), manifest_digest, None)
            .await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn returns_blob_descriptor_when_blob_filter_matches() {
        let (case, manifest_digest) = split_case_with_blob(Some("application/vnd.foo")).await;
        let registry = case.registry();

        let at = media_type("application/vnd.foo");
        let result = registry
            .resolve_referrer_descriptor(
                &referrer_namespace(),
                &subject(),
                manifest_digest,
                Some(&at),
            )
            .await;
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().artifact_type.as_deref(),
            Some("application/vnd.foo")
        );
    }

    #[tokio::test]
    async fn returns_none_when_blob_filter_mismatches() {
        let (case, manifest_digest) = split_case_with_blob(Some("application/vnd.foo")).await;
        let registry = case.registry();

        let filter = media_type("application/vnd.bar");
        let result = registry
            .resolve_referrer_descriptor(
                &referrer_namespace(),
                &subject(),
                manifest_digest,
                Some(&filter),
            )
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn returns_none_when_blob_not_found() {
        let case = FSRegistryTestCase::with_split_backends();
        let registry = case.registry();

        let result = registry
            .resolve_referrer_descriptor(
                &referrer_namespace(),
                &subject(),
                Digest::sha256(HASH_B).unwrap(),
                None,
            )
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn returns_none_when_blob_is_invalid_manifest_json() {
        let case = FSRegistryTestCase::with_split_backends();
        let registry = case.registry();
        let manifest_digest = upload_blob(registry, &referrer_namespace(), b"not json").await;

        let result = registry
            .resolve_referrer_descriptor(&referrer_namespace(), &subject(), manifest_digest, None)
            .await;
        assert!(result.is_none());
    }

    // End-to-end pin of the cross-store contract: a referrer whose link
    // carries no cached descriptor resolves through the public listing even
    // when blob and metadata stores use separate roots.
    #[tokio::test]
    async fn list_referrers_resolves_manifests_on_split_backends() {
        let (case, manifest_digest) = split_case_with_blob(Some("application/vnd.foo")).await;
        let registry = case.registry();
        create_referrer_link(&registry.metadata_store, &manifest_digest, None).await;

        let referrers = registry
            .list_referrers(&referrer_namespace(), &subject(), None)
            .await
            .unwrap();
        assert_eq!(referrers.len(), 1);
        assert_eq!(referrers[0].digest, manifest_digest);
    }
}
