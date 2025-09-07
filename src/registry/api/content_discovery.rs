use crate::registry::api::body::Body;
use crate::registry::api::hyper::request_ext::RequestExt;
use crate::registry::api::hyper::response_ext::ResponseExt;
use crate::registry::api::hyper::OCI_FILTERS_APPLIED;
use crate::registry::oci_types::{Digest, ReferrerList};
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Debug, Deserialize)]
pub struct ReferrerParameters {
    pub name: String,
    pub digest: Digest,
}

#[derive(Debug, Deserialize)]
pub struct TagsParameters {
    pub name: String,
}

pub trait RegistryAPIContentDiscoveryHandlersExt {
    async fn handle_get_referrers<T>(
        &self,
        request: Request<T>,
        parameters: ReferrerParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;

    async fn handle_list_catalog<T>(
        &self,
        request: Request<T>,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;

    async fn handle_list_tags<T>(
        &self,
        request: Request<T>,
        parameters: TagsParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl RegistryAPIContentDiscoveryHandlersExt for Registry {
    #[instrument(skip(self, request))]
    async fn handle_get_referrers<T>(
        &self,
        request: Request<T>,
        parameters: ReferrerParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
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
                .body(Body::fixed(referrer_list))?
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/vnd.oci.image.index.v1+json")
                .body(Body::fixed(referrer_list))?
        };

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_list_catalog<T>(
        &self,
        request: Request<T>,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
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

        Response::paginated(Body::fixed(catalog.into_bytes()), link.as_deref())
    }

    #[instrument(skip(self, request))]
    async fn handle_list_tags<T>(
        &self,
        request: Request<T>,
        parameters: TagsParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
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
        Response::paginated(Body::fixed(tag_list.into_bytes()), link.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::api::hyper::response_ext::IntoAsyncRead;
    use crate::registry::oci_types::Reference;
    use crate::registry::test_utils::create_test_blob;
    use crate::registry::tests::{FSRegistryTestCase, S3RegistryTestCase};
    use crate::registry::utils::BlobLink;
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Method;
    use hyper::Uri;
    use tokio::io::AsyncReadExt;

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
        let referrer_link = BlobLink::Referrer(
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
            let tag_link = BlobLink::Tag("latest".to_string());
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
            let tag_link = BlobLink::Tag(tag.to_string());
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
