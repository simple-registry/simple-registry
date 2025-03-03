use crate::registry::api::body::Body;
use crate::registry::api::hyper::request_ext::{IntoAsyncRead, RequestExt};
use crate::registry::api::hyper::{DOCKER_CONTENT_DIGEST, DOCKER_UPLOAD_UUID};
use crate::registry::data_store::DataStore;
use crate::registry::oci_types::Digest;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry, StartUploadResponse};
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, CONTENT_RANGE, LOCATION, RANGE};
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct QueryNewUploadParameters {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct QueryUploadParameters {
    pub name: String,
    pub uuid: Uuid,
}

pub trait RegistryAPIUploadHandlersExt {
    async fn handle_start_upload(
        &self,
        request: Request<Incoming>,
        parameters: QueryNewUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_get_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_patch_upload(
        &self,
        request: Request<Incoming>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_put_upload(
        &self,
        request: Request<Incoming>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_delete_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl<D: DataStore> RegistryAPIUploadHandlersExt for Registry<D> {
    #[instrument(skip(self, request))]
    async fn handle_start_upload(
        &self,
        request: Request<Incoming>,
        parameters: QueryNewUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        #[derive(Deserialize, Default)]
        struct UploadQuery {
            digest: Option<String>,
        }

        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::start_upload(&parameters.name),
            identity,
        )?;

        let query: UploadQuery = request.query_parameters()?;
        let digest = query
            .digest
            .map(|s| Digest::try_from(s.as_str()))
            .transpose()?;

        let res = match self.start_upload(&parameters.name, digest).await? {
            StartUploadResponse::ExistingBlob(digest) => Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, format!("/v2/{}/blobs/{digest}", parameters.name))
                .header(DOCKER_CONTENT_DIGEST, digest.to_string())
                .body(Body::empty())?,
            StartUploadResponse::Session(location, session_uuid) => Response::builder()
                .status(StatusCode::ACCEPTED)
                .header(LOCATION, location)
                .header(RANGE, "0-0")
                .header(DOCKER_UPLOAD_UUID, session_uuid.to_string())
                .body(Body::empty())?,
        };

        Ok(res)
    }

    #[instrument(skip(self))]
    async fn handle_get_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::get_upload(&parameters.name),
            identity,
        )?;

        let location = format!("/v2/{}/blobs/uploads/{}", parameters.name, parameters.uuid);

        let range_max = self
            .get_upload_range_max(&parameters.name, parameters.uuid)
            .await?;
        let range_max = format!("0-{range_max}");

        let res = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(LOCATION, location)
            .header(RANGE, range_max)
            .header(DOCKER_UPLOAD_UUID, parameters.uuid.to_string())
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_patch_upload(
        &self,
        request: Request<Incoming>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::update_upload(&parameters.name),
            identity,
        )?;

        let start_offset = request.range(CONTENT_RANGE)?.map(|(start, _)| start);

        let location = format!("/v2/{}/blobs/uploads/{}", &parameters.name, parameters.uuid);

        let range_max = self
            .patch_upload(
                &parameters.name,
                parameters.uuid,
                start_offset,
                request.into_async_read(),
            )
            .await?;
        let range_max = format!("0-{range_max}");

        let res = Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(LOCATION, location)
            .header(RANGE, range_max)
            .header(CONTENT_LENGTH, 0)
            .header(DOCKER_UPLOAD_UUID, parameters.uuid.to_string())
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_put_upload(
        &self,
        request: Request<Incoming>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        #[derive(Deserialize, Default)]
        struct CompleteUploadQuery {
            digest: String,
        }

        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::complete_upload(&parameters.name),
            identity,
        )?;

        let query: CompleteUploadQuery = request.query_parameters()?;
        let digest = Digest::try_from(query.digest.as_str())?;

        self.complete_upload(
            &parameters.name,
            parameters.uuid,
            digest,
            request.into_async_read(),
        )
        .await?;

        let location = format!("/v2/{}/blobs/{}", &parameters.name, query.digest);

        let res = Response::builder()
            .status(StatusCode::CREATED)
            .header(LOCATION, location)
            .header(DOCKER_CONTENT_DIGEST, query.digest)
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self))]
    async fn handle_delete_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::cancel_upload(&parameters.name),
            identity,
        )?;

        self.delete_upload(&parameters.name, parameters.uuid)
            .await?;

        let res = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())?;

        Ok(res)
    }
}
