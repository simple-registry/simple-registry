use std::collections::{HashMap, HashSet};

use futures_util::stream::{self, StreamExt, TryStreamExt};
use hyper::{
    HeaderMap, Response, StatusCode,
    header::{CONTENT_TYPE, HeaderValue, LINK},
};
use serde::Serialize;
use tracing::{instrument, warn};

use angos_storage::Page;

use crate::{
    http_response::{ResponseBody, build_response, json_headers},
    oci::{
        Content, Descriptor, Digest, Manifest, MediaType, Namespace, OCI_INDEX_MEDIA_TYPE,
        OCI_MANIFEST_SCHEMA_VERSION, Tag,
    },
    registry::{
        Error, OCI_FILTERS_APPLIED, Registry, Repository, metadata_store::LinkKind, pagination,
    },
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

/// Advertises `link` as the next page, which a listing does only while it is
/// not exhausted.
fn insert_next_link(headers: &mut HeaderMap, link: Option<&str>) -> Result<(), Error> {
    if let Some(link) = link {
        headers.insert(
            LINK,
            HeaderValue::try_from(format!("<{link}>; rel=\"next\""))?,
        );
    }

    Ok(())
}

fn paginated_json_headers(link: Option<&str>) -> Result<HeaderMap, Error> {
    let mut headers = json_headers();
    insert_next_link(&mut headers, link)?;

    Ok(headers)
}

pub struct GetReferrersRequest {
    pub namespace: Namespace,
    pub digest: Digest,
    pub artifact_type: Option<MediaType>,
    pub n: Option<u16>,
    pub last: Option<String>,
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
fn referrers_headers(artifact_type_filtered: bool, link: Option<&str>) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::try_from(OCI_INDEX_MEDIA_TYPE)?);
    if artifact_type_filtered {
        headers.insert(
            OCI_FILTERS_APPLIED,
            HeaderValue::from_static("artifactType"),
        );
    }
    insert_next_link(&mut headers, link)?;

    Ok(headers)
}

/// Whether `referrer` passes a listing's `artifactType` filter, which an
/// already-resolved descriptor is checked against rather than re-read.
fn matches_filter(referrer: &Descriptor, artifact_type: Option<&MediaType>) -> bool {
    artifact_type.is_none_or(|filter| referrer.artifact_type.as_ref() == Some(filter))
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
        // A namespace holding nothing is unknown, not empty: a client probing
        // existence here must be able to tell the two apart. A repository whose
        // tags were all deleted still holds revisions, so it stays a `200`.
        if page.items.is_empty()
            && !self
                .metadata_store
                .has_manifest_content(&request.namespace)
                .await?
        {
            return Err(Error::NameUnknown);
        }

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

    /// Resolves one page of a subject's referrers into the OCI image index that
    /// serves them, advertising the next page through the `Link` header when
    /// the listing is not exhausted.
    #[instrument(skip(request))]
    pub async fn get_referrers(
        &self,
        request: GetReferrersRequest,
    ) -> Result<Response<ResponseBody>, Error> {
        let n = request.n.unwrap_or(DEFAULT_PAGE_SIZE);
        let filter = request.artifact_type;
        let upstream = self
            .get_repository_for_namespace(&request.namespace)
            .ok()
            .filter(|repository| repository.is_pull_through());
        let page = self
            .list_referrers(
                upstream,
                &request.namespace,
                &request.digest,
                filter.clone(),
                n,
                request.last,
            )
            .await?;

        // The filter rides along on the next page: dropping it there would
        // widen the listing halfway through a client's walk.
        let namespace = &request.namespace;
        let digest = &request.digest;
        let link = page.next_token.as_ref().map(|last| {
            let filter = filter
                .as_ref()
                .map_or_else(String::new, |filter| format!("artifactType={filter}&"));
            format!("/v2/{namespace}/referrers/{digest}?{filter}n={n}&last={last}")
        });

        let body = ReferrerList {
            schema_version: OCI_MANIFEST_SCHEMA_VERSION,
            media_type: OCI_INDEX_MEDIA_TYPE,
            manifests: page.items,
        };

        Ok(build_response(
            StatusCode::OK,
            referrers_headers(filter.is_some(), link.as_deref())?,
            ResponseBody::fixed(serde_json::to_vec(&body)?),
        )?)
    }

    /// Resolves one page of `digest`'s referrers in `namespace` to a sorted
    /// descriptor list, filtered by `artifact_type` when given. `upstream` is
    /// the pull-through repository whose referrers join the local ones, or
    /// `None` to list what this registry holds alone.
    ///
    /// The page is cut over the candidate digests, so a filter that drops
    /// entries yields a page shorter than `n` while the continuation token
    /// still names where to resume.
    #[instrument(skip(upstream))]
    pub async fn list_referrers(
        &self,
        upstream: Option<&Repository>,
        namespace: &Namespace,
        digest: &Digest,
        artifact_type: Option<MediaType>,
        n: u16,
        last: Option<String>,
    ) -> Result<Page<Descriptor>, Error> {
        let artifact_type = artifact_type.as_ref();
        // Referrers no local index knows: an upstream's, and any a pre-API
        // client left under the fallback tag. Both arrive resolved.
        let mut described = self
            .upstream_referrers(upstream, namespace, digest, artifact_type)
            .await;
        for referrer in self.fallback_tag_referrers(namespace, digest).await {
            if matches_filter(&referrer, artifact_type) {
                described.entry(referrer.digest.clone()).or_insert(referrer);
            }
        }

        let local: HashSet<Digest> = self
            .metadata_store
            .stream_referrer_digests(namespace, digest)
            .try_collect()
            .await?;
        let mut candidates: Vec<Digest> = local
            .iter()
            .chain(described.keys().filter(|digest| !local.contains(*digest)))
            .cloned()
            .collect();
        candidates.sort();

        let page = pagination::paginate_sorted(&candidates, n, last.as_deref());
        // Up to `REFERRER_RESOLVE_CONCURRENCY` local candidates resolve at once,
        // each one an independent manifest read. A candidate the local index
        // does not hold is already resolved, its descriptor coming with it.
        let (local, described) = (&local, &described);
        let mut referrers: Vec<Descriptor> = stream::iter(page.items)
            .map(async |manifest_digest| {
                if local.contains(&manifest_digest) {
                    return self
                        .resolve_referrer_descriptor(
                            namespace,
                            digest,
                            manifest_digest,
                            artifact_type,
                        )
                        .await;
                }
                described.get(&manifest_digest).cloned()
            })
            .buffer_unordered(REFERRER_RESOLVE_CONCURRENCY)
            .filter_map(|descriptor| async move { descriptor })
            .collect()
            .await;

        referrers.sort_by(|a, b| a.digest.cmp(&b.digest));
        Ok(Page {
            items: referrers,
            next_token: page.next_token,
        })
    }

    /// The referrers a pre-API client recorded under the fallback tag
    /// (`sha256-<hex>`), which the spec's "Enabling the Referrers API"
    /// procedure has a registry fold into the listing: a repository imported
    /// from a registry whose clients used the fallback would otherwise lose
    /// them. Costs one link read per listing, which misses on a subject that
    /// never had one.
    async fn fallback_tag_referrers(
        &self,
        namespace: &Namespace,
        subject: &Digest,
    ) -> Vec<Descriptor> {
        let Ok(tag) = Tag::new(&format!("{}-{}", subject.algorithm(), subject.hash())) else {
            return Vec::new();
        };
        let Ok(link) = self
            .metadata_store
            .read_link(namespace, &LinkKind::Tag(tag))
            .await
        else {
            return Vec::new();
        };
        let Ok(body) = self.blob_store.read(&link.target).await else {
            return Vec::new();
        };

        match Manifest::from_slice(&body).map(|index| index.content) {
            Ok(Content::Index { manifests }) => manifests,
            _ => Vec::new(),
        }
    }

    /// The referrers `upstream` holds for `digest`, keyed by their own digest
    /// and filtered like the local ones. Nothing fills a referrer index on its
    /// own, so a pull-through namespace that listed only what it cached would
    /// answer an uncached subject with nothing at all.
    ///
    /// An upstream that cannot be reached yields none: a mirror still lists
    /// what it holds when its upstream is down.
    async fn upstream_referrers(
        &self,
        upstream: Option<&Repository>,
        namespace: &Namespace,
        digest: &Digest,
        artifact_type: Option<&MediaType>,
    ) -> HashMap<Digest, Descriptor> {
        let Some(repository) = upstream else {
            return HashMap::new();
        };

        match repository.list_referrers(namespace, digest).await {
            Ok(referrers) => referrers
                .into_iter()
                .filter(|referrer| matches_filter(referrer, artifact_type))
                .map(|referrer| (referrer.digest.clone(), referrer))
                .collect(),
            Err(error) => {
                warn!("Upstream referrer listing failed for {namespace}@{digest}: {error}");
                HashMap::new()
            }
        }
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
                        Some(manifest.take_descriptor(manifest_digest, manifest_len as u64))
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

    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::{
        DEFAULT_PAGE_SIZE, GetReferrersRequest, ListCatalogRequest, ListTagsRequest,
        OCI_INDEX_MEDIA_TYPE, Repository, Response, ResponseBody,
    };

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

    /// The `field` of every object in a response's `array` field.
    async fn json_strings_at(
        response: Response<ResponseBody>,
        array: &str,
        field: &str,
    ) -> Vec<String> {
        response_json(response).await[array]
            .as_array()
            .expect("the listing field must be an array")
            .iter()
            .map(|entry| {
                entry[field]
                    .as_str()
                    .expect("entries carry the field")
                    .to_string()
            })
            .collect()
    }

    fn next_cursor(response: &Response<ResponseBody>) -> Option<String> {
        let link = response.headers().get(LINK)?.to_str().ok()?;
        let (_, last) = link.rsplit_once("last=")?;
        Some(last.trim_end_matches(">; rel=\"next\"").to_string())
    }
    use crate::{
        cache,
        oci::{Descriptor, Digest, Manifest, MediaType, Namespace, Reference, Tag},
        registry::{
            Error,
            manifest::DEFAULT_MAX_MANIFEST_SIZE_BYTES,
            metadata_store::{LinkKind, LinkOperation, MetadataStore},
            repository::Config,
            test_utils::{
                FSRegistryTestCase, create_test_blob, for_each_backend, media_type,
                put_blob_direct, response_json, upload_blob,
            },
        },
        test_fixtures::client::test_client_config,
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

    // A namespace that has never been written is unknown, not empty: a client
    // probing existence through this endpoint must be able to tell them apart.
    #[tokio::test]
    async fn list_tag_entries_unknown_namespace_is_not_found() {
        let test_case = crate::registry::test_utils::FSRegistryTestCase::new();
        let registry = test_case.registry();

        let result = registry
            .list_tag_entries(ListTagsRequest {
                namespace: Namespace::new("no-such-repo/no-such-image").unwrap(),
                n: None,
                last: None,
            })
            .await;

        assert!(
            matches!(result, Err(Error::NameUnknown)),
            "a namespace holding nothing must be unknown, got {result:?}"
        );
    }

    // The other half of the same rule: a namespace whose tags were all deleted
    // still holds a revision, so it is an empty repository rather than a
    // missing one.
    #[tokio::test]
    async fn list_tag_entries_serves_a_namespace_whose_tags_are_gone() {
        let test_case = crate::registry::test_utils::FSRegistryTestCase::new();
        let registry = test_case.registry();
        let namespace = Namespace::new("test-repo").unwrap();

        let digest = put_blob_direct(registry.metadata_store.store(), b"revision body").await;
        registry
            .metadata_store
            .update_links(
                &namespace,
                &[LinkOperation::create(
                    LinkKind::Digest(digest.clone()),
                    digest,
                )],
            )
            .await
            .unwrap();

        let response = registry
            .list_tag_entries(ListTagsRequest {
                namespace,
                n: None,
                last: None,
            })
            .await
            .expect("a namespace holding a revision must be served");

        assert!(next_cursor(&response).is_none());
        assert!(
            tags(response).await.is_empty(),
            "a namespace with no tags must serve an empty list"
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
                .list_referrers(None, namespace, &base_manifest_digest, None, DEFAULT_PAGE_SIZE, None)
                .await
                .unwrap();

            assert_eq!(referrers.items.len(), 1);
            assert_eq!(referrers.items[0].digest, referrer_manifest_digest);
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

    /// A pull-through repository owning `mirror/*`, so a request for
    /// `mirror/app` maps to the upstream's `app`.
    async fn pull_through_repository(upstream: &str) -> Repository {
        let config = Config {
            upstream: vec![test_client_config(upstream)],
            ..Default::default()
        };
        let cache_backend = cache::Config::Memory.to_backend().unwrap();
        Repository::new(
            "mirror",
            &config,
            &cache_backend,
            DEFAULT_MAX_MANIFEST_SIZE_BYTES,
        )
        .await
        .unwrap()
    }

    /// Creates the referrer link `subject() -> manifest`, optionally carrying
    /// a cached descriptor.
    async fn create_referrer_link(
        m: &MetadataStore,
        namespace: &Namespace,
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
        m.update_links(namespace, &ops).await.unwrap();
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
            &referrer_namespace(),
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
            &referrer_namespace(),
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
        create_referrer_link(
            &registry.metadata_store,
            &referrer_namespace(),
            &manifest_digest,
            Some(desc),
        )
        .await;

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
        create_referrer_link(
            &registry.metadata_store,
            &referrer_namespace(),
            &manifest_digest,
            Some(desc),
        )
        .await;

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
        create_referrer_link(
            &registry.metadata_store,
            &referrer_namespace(),
            &manifest_digest,
            None,
        )
        .await;

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

    /// A repository imported from a registry whose clients used the referrers
    /// fallback tag keeps those entries: the spec's "Enabling the Referrers
    /// API" procedure has the tag's index folded into the listing.
    #[tokio::test]
    async fn list_referrers_merges_the_fallback_tag_index() {
        let case = FSRegistryTestCase::with_split_backends();
        let registry = case.registry();
        let namespace = referrer_namespace();
        let subject = subject();

        let indexed = Digest::sha256_of_bytes(b"referrer the index knows");
        create_referrer_link(
            &registry.metadata_store,
            &namespace,
            &indexed,
            Some(descriptor_with(None, &indexed)),
        )
        .await;

        // The fallback tag an older client would have pushed: an index whose
        // manifests are the referrers of the subject.
        let tagged = Digest::sha256_of_bytes(b"referrer only the tag knows");
        let fallback = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "manifests": [descriptor_with(None, &tagged)],
        }))
        .unwrap();
        let fallback_digest = upload_blob(registry, &namespace, &fallback).await;
        let tag = Tag::new(&format!("{}-{}", subject.algorithm(), subject.hash())).unwrap();
        registry
            .metadata_store
            .update_links(
                &namespace,
                &[LinkOperation::create(
                    LinkKind::Tag(tag),
                    fallback_digest.clone(),
                )],
            )
            .await
            .unwrap();

        let page = registry
            .list_referrers(None, &namespace, &subject, None, DEFAULT_PAGE_SIZE, None)
            .await
            .unwrap();

        let mut served: Vec<Digest> = page.items.into_iter().map(|d| d.digest).collect();
        served.sort();
        let mut expected = vec![indexed, tagged];
        expected.sort();
        assert_eq!(
            served, expected,
            "the listing must hold both the indexed and the fallback-tagged referrer"
        );
    }

    /// A pull-through namespace lists what the upstream holds alongside what it
    /// cached: nothing ever fills a referrer index on its own, so an uncached
    /// subject would otherwise answer with nothing at all.
    #[tokio::test]
    async fn list_referrers_merges_the_upstream_listing() {
        let case = FSRegistryTestCase::with_split_backends();
        let registry = case.registry();
        let namespace = Namespace::new("mirror/app").unwrap();
        let cached = Digest::sha256_of_bytes(b"cached referrer");
        create_referrer_link(
            &registry.metadata_store,
            &namespace,
            &cached,
            Some(descriptor_with(None, &cached)),
        )
        .await;

        let remote = Digest::sha256_of_bytes(b"upstream referrer");
        let subject = subject();
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/app/referrers/{subject}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schemaVersion": 2,
                "mediaType": OCI_INDEX_MEDIA_TYPE,
                "manifests": [descriptor_with(None, &remote)],
            })))
            .mount(&mock_server)
            .await;
        let repository = pull_through_repository(&mock_server.uri()).await;

        let page = registry
            .list_referrers(
                Some(&repository),
                &namespace,
                &subject,
                None,
                DEFAULT_PAGE_SIZE,
                None,
            )
            .await
            .unwrap();

        let mut served: Vec<Digest> = page.items.into_iter().map(|d| d.digest).collect();
        served.sort();
        let mut expected = vec![cached, remote];
        expected.sort();
        assert_eq!(
            served, expected,
            "a pull-through listing must hold the cached and the upstream referrer"
        );
    }

    /// An upstream that cannot be reached must not take the cached referrers
    /// down with it.
    #[tokio::test]
    async fn list_referrers_serves_the_cache_when_the_upstream_fails() {
        let case = FSRegistryTestCase::with_split_backends();
        let registry = case.registry();
        let namespace = Namespace::new("mirror/app").unwrap();
        let cached = Digest::sha256_of_bytes(b"cached referrer");
        create_referrer_link(
            &registry.metadata_store,
            &namespace,
            &cached,
            Some(descriptor_with(None, &cached)),
        )
        .await;
        let repository = pull_through_repository("http://127.0.0.1:1").await;

        let page = registry
            .list_referrers(
                Some(&repository),
                &namespace,
                &subject(),
                None,
                DEFAULT_PAGE_SIZE,
                None,
            )
            .await
            .unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].digest, cached);
    }

    // End-to-end pin of the cross-store contract: a referrer whose link
    // carries no cached descriptor resolves through the public listing even
    // when blob and metadata stores use separate roots.
    #[tokio::test]
    async fn list_referrers_resolves_manifests_on_split_backends() {
        let (case, manifest_digest) = split_case_with_blob(Some("application/vnd.foo")).await;
        let registry = case.registry();
        create_referrer_link(
            &registry.metadata_store,
            &referrer_namespace(),
            &manifest_digest,
            None,
        )
        .await;

        let referrers = registry
            .list_referrers(
                None,
                &referrer_namespace(),
                &subject(),
                None,
                DEFAULT_PAGE_SIZE,
                None,
            )
            .await
            .unwrap();
        assert_eq!(referrers.items.len(), 1);
        assert_eq!(referrers.items[0].digest, manifest_digest);
    }

    /// A wide fan-out is served one page at a time: following `Link` visits
    /// every referrer exactly once and no single response carries them all.
    #[tokio::test]
    async fn get_referrers_pages_through_the_fan_out() {
        let case = FSRegistryTestCase::with_split_backends();
        let registry = case.registry();

        // A cached descriptor answers each candidate, so the page size alone
        // decides how many entries a response resolves.
        let mut expected = Vec::new();
        for index in 0..5u8 {
            let digest = Digest::sha256_of_bytes([index]);
            create_referrer_link(
                &registry.metadata_store,
                &referrer_namespace(),
                &digest,
                Some(descriptor_with(None, &digest)),
            )
            .await;
            expected.push(digest.to_string());
        }
        expected.sort();

        let mut served = Vec::new();
        let mut last = None;
        loop {
            let response = registry
                .get_referrers(GetReferrersRequest {
                    namespace: referrer_namespace(),
                    digest: subject(),
                    artifact_type: None,
                    n: Some(2),
                    last,
                })
                .await
                .unwrap();
            let cursor = next_cursor(&response);
            let page = json_strings_at(response, "manifests", "digest").await;
            assert!(page.len() <= 2, "a page must not exceed the requested size");
            served.extend(page);

            // Follow the advertised `Link` exactly as a paging client would.
            match cursor {
                None => break,
                Some(cursor) => last = Some(cursor),
            }
        }

        assert_eq!(
            served, expected,
            "paging must visit every referrer exactly once, in digest order"
        );
    }
}
