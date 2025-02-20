use crate::registry::api::body::Body;
use crate::registry::data_store::DataStore;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry};
use hyper::{Response, StatusCode};
use tracing::instrument;

pub trait RegistryAPIVersionHandlerExt {
    async fn handle_get_api_version(
        &self,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl<D: DataStore> RegistryAPIVersionHandlerExt for Registry<D> {
    #[instrument(skip(self))]
    async fn handle_get_api_version(
        &self,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        self.validate_request(None, ClientRequest::get_api_version(), identity)?;

        let res = Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Distribution-API-Version", "registry/2.0")
            .header("X-Powered-By", "Simple-Registry")
            .body(Body::empty())?;

        Ok(res)
    }
}
