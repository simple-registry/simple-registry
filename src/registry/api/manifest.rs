use crate::registry::api::body::Body;
use crate::registry::api::hyper::request_ext::RequestExt;
use crate::registry::api::hyper::{DOCKER_CONTENT_DIGEST, OCI_SUBJECT};
use crate::registry::data_store::DataStore;
use crate::registry::oci_types::Reference;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use tracing::instrument;

#[derive(Debug, Deserialize)]
pub struct QueryManifestParameters {
    pub name: String,
    pub reference: Reference,
}

pub trait RegistryAPIManifestHandlersExt {
    async fn handle_head_manifest(
        &self,
        request: Request<Incoming>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_get_manifest(
        &self,
        request: Request<Incoming>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;

    async fn handle_put_manifest(
        &self,
        request: Request<Incoming>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;

    async fn handle_delete_manifest(
        &self,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl<D: DataStore> RegistryAPIManifestHandlersExt for Registry<D> {
    #[instrument(skip(self, request))]
    async fn handle_head_manifest(
        &self,
        request: Request<Incoming>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::get_manifest(&parameters.name, &parameters.reference),
            identity,
        )?;

        let manifest = self
            .head_manifest(
                repository,
                &request.accepted_content_types(),
                &parameters.name,
                parameters.reference,
            )
            .await?;

        let res = if let Some(media_type) = manifest.media_type {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, media_type)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .header(CONTENT_LENGTH, manifest.size)
                .body(Body::empty())?
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .header(CONTENT_LENGTH, manifest.size)
                .body(Body::empty())?
        };

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_get_manifest(
        &self,
        request: Request<Incoming>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::get_manifest(&parameters.name, &parameters.reference),
            identity,
        )?;

        let manifest = self
            .get_manifest(
                repository,
                &request.accepted_content_types(),
                &parameters.name,
                parameters.reference,
            )
            .await?;

        let res = if let Some(content_type) = manifest.media_type {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, content_type)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .body(Body::fixed(manifest.content))?
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .body(Body::fixed(manifest.content))?
        };

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_put_manifest(
        &self,
        request: Request<Incoming>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::put_manifest(&parameters.name, &parameters.reference),
            identity,
        )?;

        let content_type = request
            .get_header(CONTENT_TYPE)
            .ok_or(Error::ManifestInvalid(
                "No Content-Type header provided".to_string(),
            ))?;

        let request_body = request.into_body().collect().await.map_err(|_| {
            Error::ManifestInvalid("Unable to retrieve manifest from client query".to_string())
        })?;
        let body = request_body.to_bytes();

        let location = format!("/v2/{}/manifests/{}", parameters.name, parameters.reference);

        let manifest = self
            .put_manifest(
                &parameters.name,
                parameters.reference,
                Some(&content_type),
                &body,
            )
            .await?;

        let res = match manifest.subject {
            Some(subject) => Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, location)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .header(OCI_SUBJECT, subject.to_string())
                .body(Body::empty())?,
            None => Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, location)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .body(Body::empty())?,
        };

        Ok(res)
    }

    #[instrument(skip(self))]
    async fn handle_delete_manifest(
        &self,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::delete_manifest(&parameters.name, &parameters.reference),
            identity,
        )?;

        self.delete_manifest(&parameters.name, parameters.reference)
            .await?;

        let res = Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Body::empty())?;

        Ok(res)
    }
}
