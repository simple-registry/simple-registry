use crate::registry::api::body::Body;
use crate::registry::api::hyper::request_ext::RequestExt;
use crate::registry::api::hyper::response_ext::ResponseExt;
use crate::registry::data_store::DataStore;
use crate::registry::oci_types::{Digest, ReferrerList};
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry};
use hyper::body::Incoming;
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
    async fn handle_get_referrers(
        &self,
        request: Request<Incoming>,
        parameters: ReferrerParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;

    async fn handle_list_catalog(
        &self,
        request: Request<Incoming>,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;

    async fn handle_list_tags(
        &self,
        request: Request<Incoming>,
        parameters: TagsParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl<D: DataStore> RegistryAPIContentDiscoveryHandlersExt for Registry<D> {
    #[instrument(skip(self, request))]
    async fn handle_get_referrers(
        &self,
        request: Request<Incoming>,
        parameters: ReferrerParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct GetReferrersQuery {
            artifact_type: Option<String>,
        }

        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::get_referrers(&parameters.name, &parameters.digest),
            identity,
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
                .header("Content-Type", "application/vnd.oci.image.index.v1+json")
                .header("OCI-Filters-Applied", "artifactType")
                .body(Body::fixed(referrer_list))?
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/vnd.oci.image.index.v1+json")
                .body(Body::fixed(referrer_list))?
        };

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_list_catalog(
        &self,
        request: Request<Incoming>,
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

        self.validate_request(None, ClientRequest::list_catalog(), identity)?;

        let query: CatalogQuery = request.query_parameters()?;

        let (repositories, link) = self.list_catalog(query.n, query.last).await?;

        let catalog = CatalogResponse { repositories };
        let catalog = serde_json::to_string(&catalog)?;

        Response::paginated(Body::fixed(catalog.into_bytes()), link.as_deref())
    }

    #[instrument(skip(self, request))]
    async fn handle_list_tags(
        &self,
        request: Request<Incoming>,
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
        self.validate_request(
            Some(repository),
            ClientRequest::list_tags(&parameters.name),
            identity,
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
