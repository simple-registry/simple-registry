use crate::registry::oci::{Descriptor, Digest, ReferrerList};
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::utils::request_ext::RequestExt;
use crate::registry::utils::response_ext::ResponseExt;
use crate::registry::{Error, Registry, ResponseBody};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::instrument;

pub const OCI_FILTERS_APPLIED: &str = "OCI-Filters-Applied";

#[derive(Debug, Deserialize)]
pub struct ReferrerParameters {
    pub name: String,
    pub digest: Digest,
}

#[derive(Debug, Deserialize)]
pub struct TagsParameters {
    pub name: String,
}

impl Registry {
    #[instrument]
    pub async fn get_referrers(
        &self,
        namespace: &str,
        digest: Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, Error> {
        self.validate_namespace(namespace)?;

        Ok(self
            .metadata_store
            .list_referrers(namespace, &digest, artifact_type)
            .await?)
    }

    #[instrument]
    pub async fn list_catalog(
        &self,
        n: Option<u16>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let n = n.unwrap_or(100);

        let (namespaces, next_last) = self.metadata_store.list_namespaces(n, last).await?;
        let link = next_last.map(|next_last| format!("/v2/_catalog?n={n}&last={next_last}"));

        let namespaces = namespaces
            .into_iter()
            .map(|digest| digest.to_string())
            .collect();
        Ok((namespaces, link))
    }

    #[instrument]
    pub async fn list_tags(
        &self,
        namespace: &str,
        n: Option<u16>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        self.validate_namespace(namespace)?;

        let n = n.unwrap_or(100);

        let (tags, next_last) = self.metadata_store.list_tags(namespace, n, last).await?;
        let link =
            next_last.map(|next_last| format!("/v2/{namespace}/tags/list?n={n}&last={next_last}"));

        Ok((tags, link))
    }

    // API Handlers
    #[instrument(skip(self, request))]
    pub async fn handle_get_referrers<T>(
        &self,
        request: Request<T>,
        parameters: ReferrerParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct GetReferrersQuery {
            artifact_type: Option<String>,
        }

        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::get_referrers(&parameters.name, &parameters.digest),
            &identity,
        )?;

        let query: GetReferrersQuery = request.query_parameters()?;
        let query_supplied_artifact_type = query.artifact_type.is_some();

        let manifests = self
            .get_referrers(&parameters.name, parameters.digest, query.artifact_type)
            .await?;

        let referrer_list = ReferrerList {
            manifests,
            ..ReferrerList::default()
        };
        let referrer_list = serde_json::to_string(&referrer_list)?.into_bytes();

        let res = if query_supplied_artifact_type {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/vnd.oci.image.index.v1+json")
                .header(OCI_FILTERS_APPLIED, "artifactType")
                .body(ResponseBody::fixed(referrer_list))?
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/vnd.oci.image.index.v1+json")
                .body(ResponseBody::fixed(referrer_list))?
        };

        Ok(res)
    }

    #[instrument(skip(self, request))]
    pub async fn handle_list_catalog<T>(
        &self,
        request: Request<T>,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
        #[derive(Debug, Deserialize, Default)]
        struct CatalogQuery {
            n: Option<u16>,
            last: Option<String>,
        }

        #[derive(Serialize, Debug)]
        struct CatalogResponse {
            repositories: Vec<String>,
        }

        Self::validate_request(None, &ClientRequest::list_catalog(), &identity)?;

        let query: CatalogQuery = request.query_parameters()?;

        let (repositories, link) = self.list_catalog(query.n, query.last).await?;

        let catalog = CatalogResponse { repositories };
        let catalog = serde_json::to_string(&catalog)?;

        Response::paginated(ResponseBody::fixed(catalog.into_bytes()), link.as_deref())
    }

    #[instrument(skip(self, request))]
    pub async fn handle_list_tags<T>(
        &self,
        request: Request<T>,
        parameters: TagsParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
        #[derive(Deserialize, Debug, Default)]
        struct TagsQuery {
            n: Option<u16>,
            last: Option<String>,
        }

        #[derive(Serialize, Debug)]
        struct TagsResponse {
            name: String,
            tags: Vec<String>,
        }

        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::list_tags(&parameters.name),
            &identity,
        )?;

        let query: TagsQuery = request.query_parameters()?;

        let (tags, link) = self
            .list_tags(&parameters.name, query.n, query.last)
            .await?;

        let tag_list = TagsResponse {
            name: parameters.name.to_string(),
            tags,
        };
        let tag_list = serde_json::to_string(&tag_list)?;
        Response::paginated(ResponseBody::fixed(tag_list.into_bytes()), link.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::metadata_store::link_kind::LinkKind;
    use crate::registry::oci::Reference;
    use crate::registry::policy_types::ClientIdentity;
    use crate::registry::test_utils::create_test_blob;
    use crate::registry::tests::{FSRegistryTestCase, S3RegistryTestCase};
    use crate::registry::utils::response_ext::{IntoAsyncRead, ResponseExt};
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Method;
    use hyper::Uri;
    use std::str::FromStr;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_get_referrers_fs() {
        let t = FSRegistryTestCase::new();
        test_get_referrers(t.registry()).await;
    }

    #[tokio::test]
    async fn test_get_referrers_s3() {
        let t = S3RegistryTestCase::new();
        test_get_referrers(t.registry()).await;
    }

    async fn test_get_referrers(registry: &Registry) {
        let namespace = "test-repo";
        let digest = Digest::from_str(
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap();

        // Create a link to make the namespace valid
        let test_content = b"test content";
        let test_digest = registry.blob_store.create_blob(test_content).await.unwrap();
        let tag_link = LinkKind::Tag("latest".to_string());
        registry
            .metadata_store
            .create_link(namespace, &tag_link, &test_digest)
            .await
            .unwrap();

        // Test empty referrers list
        let referrers = registry
            .get_referrers(namespace, digest.clone(), None)
            .await
            .unwrap();
        assert!(referrers.is_empty());

        // Test with artifact type filter
        let referrers = registry
            .get_referrers(namespace, digest.clone(), Some("test-type".to_string()))
            .await
            .unwrap();
        assert!(referrers.is_empty());
    }

    #[tokio::test]
    async fn test_list_catalog_fs() {
        let t = FSRegistryTestCase::new();
        test_list_catalog(t.registry()).await;
    }

    #[tokio::test]
    async fn test_list_catalog_s3() {
        let t = S3RegistryTestCase::new();
        test_list_catalog(t.registry()).await;
    }

    async fn test_list_catalog(registry: &Registry) {
        // Test default pagination (n=100)
        let (namespaces, token) = registry.list_catalog(None, None).await.unwrap();
        assert!(namespaces.is_empty());
        assert!(token.is_none());

        // Test custom pagination
        let (namespaces, token) = registry.list_catalog(Some(10), None).await.unwrap();
        assert!(namespaces.is_empty());
        assert!(token.is_none());

        // Test with last token
        let (namespaces, token) = registry
            .list_catalog(Some(10), Some("test".to_string()))
            .await
            .unwrap();
        assert!(namespaces.is_empty());
        assert!(token.is_none());
    }

    #[tokio::test]
    async fn test_list_tags_fs() {
        let t = FSRegistryTestCase::new();
        test_list_tags(t.registry()).await;
    }

    #[tokio::test]
    async fn test_list_tags_s3() {
        let t = S3RegistryTestCase::new();
        test_list_tags(t.registry()).await;
    }

    async fn test_list_tags(registry: &Registry) {
        let namespace = "test-repo";

        // Create some tags first
        let test_content = b"test content";
        let test_digest = registry.blob_store.create_blob(test_content).await.unwrap();
        let tags = ["latest", "v1.0", "v2.0"];
        for tag in tags {
            let tag_link = LinkKind::Tag(tag.to_string());
            registry
                .metadata_store
                .create_link(namespace, &tag_link, &test_digest)
                .await
                .unwrap();
        }

        // Test default pagination (n=100)
        let (tags, token) = registry.list_tags(namespace, None, None).await.unwrap();
        assert_eq!(tags.len(), 3);
        assert!(tags.contains(&"latest".to_string()));
        assert!(tags.contains(&"v1.0".to_string()));
        assert!(tags.contains(&"v2.0".to_string()));
        assert!(token.is_none());

        // Test custom pagination (2 items per page)
        let (page1, token1) = registry.list_tags(namespace, Some(2), None).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(token1.is_some());

        // Extract the last tag from the token URL
        let last_tag = token1.unwrap().split("last=").nth(1).unwrap().to_string();

        let (page2, token2) = registry
            .list_tags(namespace, Some(2), Some(last_tag))
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_none());

        // Test custom pagination (1 item per page)
        let (page1, token1) = registry.list_tags(namespace, Some(1), None).await.unwrap();
        assert_eq!(page1.len(), 1);
        assert!(token1.is_some());

        // Extract the last tag from the token URL
        let last_tag = token1.unwrap().split("last=").nth(1).unwrap().to_string();

        let (page2, token2) = registry
            .list_tags(namespace, Some(1), Some(last_tag))
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_some());

        // Extract the last tag from the token URL
        let last_tag = token2.unwrap().split("last=").nth(1).unwrap().to_string();

        let (page3, token3) = registry
            .list_tags(namespace, Some(1), Some(last_tag))
            .await
            .unwrap();
        assert_eq!(page3.len(), 1);
        assert!(token3.is_none());

        // Test with last token beyond the end
        let (tags, token) = registry
            .list_tags(namespace, Some(10), Some("latest".to_string()))
            .await
            .unwrap();
        assert_eq!(tags.len(), 2);
        assert!(token.is_none());
    }

    // API Handler Tests
    async fn test_handle_get_referrers_impl(registry: &Registry) {
        let namespace = "test-repo";

        // Create manifest blobs
        let manifest_content = r#"{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"}"#;
        let media_type = "application/vnd.docker.distribution.manifest.v2+json".to_string();

        // Put base manifest
        let (base_manifest_digest, _) =
            create_test_blob(registry, namespace, manifest_content.as_bytes()).await;
        registry
            .put_manifest(
                namespace,
                Reference::Digest(base_manifest_digest.clone()),
                Some(&media_type),
                manifest_content.as_bytes(),
            )
            .await
            .unwrap();

        // Put referrer manifest
        let (referrer_manifest_digest, _) =
            create_test_blob(registry, namespace, manifest_content.as_bytes()).await;
        registry
            .put_manifest(
                namespace,
                Reference::Digest(referrer_manifest_digest.clone()),
                Some(&media_type),
                manifest_content.as_bytes(),
            )
            .await
            .unwrap();

        // Create a referrer link
        let referrer_link = LinkKind::Referrer(
            base_manifest_digest.clone(),
            referrer_manifest_digest.clone(),
        );
        registry
            .metadata_store
            .create_link(namespace, &referrer_link, &referrer_manifest_digest)
            .await
            .unwrap();

        // Test getting referrers
        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/referrers/{base_manifest_digest}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let parameters = ReferrerParameters {
            name: namespace.to_string(),
            digest: base_manifest_digest.clone(),
        };

        let response = registry
            .handle_get_referrers(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let mut reader = response.into_async_read();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        let referrers: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let manifests = referrers["manifests"].as_array().unwrap();
        assert_eq!(manifests.len(), 1);
        assert_eq!(
            manifests[0]["digest"].as_str().unwrap(),
            referrer_manifest_digest.to_string()
        );
    }

    #[tokio::test]
    async fn test_handle_get_referrers_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_get_referrers_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_get_referrers_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_get_referrers_impl(t.registry()).await;
    }

    async fn test_handle_list_catalog_impl(registry: &Registry) {
        // Create some test repositories
        let namespaces = ["repo1", "repo2", "repo3"];
        let content = b"test content";

        for namespace in &namespaces {
            let (digest, _) = create_test_blob(registry, namespace, content).await;
            let tag_link = LinkKind::Tag("latest".to_string());
            registry
                .metadata_store
                .create_link(namespace, &tag_link, &digest)
                .await
                .unwrap();
        }

        // Test without pagination
        let request = Request::builder()
            .method(Method::GET)
            .uri(Uri::from_static("/v2/_catalog"))
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = registry
            .handle_list_catalog(request, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let has_link = response.get_header("Link").is_some();
        let mut reader = response.into_async_read();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        let catalog: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let repositories = catalog["repositories"].as_array().unwrap();
        assert_eq!(repositories.len(), namespaces.len());
        for namespace in &namespaces {
            assert!(repositories
                .iter()
                .any(|r| r.as_str().unwrap() == *namespace));
        }
        assert!(!has_link);

        // Test with pagination
        let request = Request::builder()
            .method(Method::GET)
            .uri(Uri::from_static("/v2/_catalog?n=2"))
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = registry
            .handle_list_catalog(request, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let has_link = response.get_header("Link").is_some();
        let mut reader = response.into_async_read();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        let catalog: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let repositories = catalog["repositories"].as_array().unwrap();
        assert_eq!(repositories.len(), 2);
        assert!(has_link);
    }

    #[tokio::test]
    async fn test_handle_list_catalog_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_list_catalog_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_list_catalog_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_list_catalog_impl(t.registry()).await;
    }

    async fn test_handle_list_tags_impl(registry: &Registry) {
        let namespace = "test-repo";
        let content = b"test content";
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        // Create some test tags
        let tags = ["v1", "v2", "latest"];
        for tag in tags {
            let tag_link = LinkKind::Tag(tag.to_string());
            registry
                .metadata_store
                .create_link(namespace, &tag_link, &digest)
                .await
                .unwrap();
        }

        // Test without pagination
        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/tags/list"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let parameters = TagsParameters {
            name: namespace.to_string(),
        };

        let response = registry
            .handle_list_tags(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let has_link = response.get_header("Link").is_some();
        let mut reader = response.into_async_read();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        let tag_list: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        let name = tag_list["name"].as_str().unwrap();
        let returned_tags = tag_list["tags"].as_array().unwrap();

        assert_eq!(name, namespace);
        assert_eq!(returned_tags.len(), tags.len());

        for tag in &tags {
            assert!(returned_tags.iter().any(|t| t.as_str().unwrap() == *tag));
        }
        assert!(!has_link);

        // Test with pagination
        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/tags/list?n=2"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let parameters = TagsParameters {
            name: namespace.to_string(),
        };

        let response = registry
            .handle_list_tags(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let has_link = response.get_header("Link").is_some();
        let mut reader = response.into_async_read();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        let tag_list: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        let name = tag_list["name"].as_str().unwrap();
        let tags = tag_list["tags"].as_array().unwrap();

        assert_eq!(name, namespace);
        assert_eq!(tags.len(), 2);
        assert!(has_link);
    }

    #[tokio::test]
    async fn test_handle_list_tags_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_list_tags_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_list_tags_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_list_tags_impl(t.registry()).await;
    }
}
