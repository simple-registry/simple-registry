use crate::registry::api::body::Body;
use crate::registry::api::hyper::request_ext::RequestExt;
use crate::registry::api::hyper::DOCKER_CONTENT_DIGEST;
use crate::registry::blob::GetBlobResponse;
use crate::registry::data_store::DataStore;
use crate::registry::oci_types::Digest;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry};
use hyper::body::Incoming;
use hyper::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tracing::instrument;

#[derive(Debug, Deserialize)]
pub struct QueryBlobParameters {
    pub name: String,
    pub digest: Digest,
}

pub trait RegistryAPIBlobHandlersExt {
    async fn handle_head_blob(
        &self,
        request: Request<Incoming>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_delete_blob(
        &self,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_get_blob(
        &self,
        request: Request<Incoming>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl<D: DataStore + 'static> RegistryAPIBlobHandlersExt for Registry<D> {
    #[instrument(skip(self, request))]
    async fn handle_head_blob(
        &self,
        request: Request<Incoming>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::get_blob(&parameters.name, &parameters.digest),
            identity,
        )?;

        let blob = self
            .head_blob(
                repository,
                &request.accepted_content_types(),
                &parameters.name,
                parameters.digest,
            )
            .await?;

        let res = Response::builder()
            .status(StatusCode::OK)
            .header(DOCKER_CONTENT_DIGEST, blob.digest.to_string())
            .header(CONTENT_LENGTH, blob.size.to_string())
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self))]
    async fn handle_delete_blob(
        &self,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::delete_blob(&parameters.name, &parameters.digest),
            identity,
        )?;

        self.delete_blob(&parameters.name, parameters.digest)
            .await?;

        let res = Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_get_blob(
        &self,
        request: Request<Incoming>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        self.validate_request(
            Some(repository),
            ClientRequest::get_blob(&parameters.name, &parameters.digest),
            identity,
        )?;

        let res = match self
            .get_blob(
                repository,
                &request.accepted_content_types(),
                &parameters.name,
                &parameters.digest,
                request.range(RANGE)?,
            )
            .await?
        {
            GetBlobResponse::RangedReader(reader, (start, end), total_length) => {
                let length = end - start + 1;
                let stream = reader.take(length);
                let range = format!("bytes {start}-{end}/{total_length}");

                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(DOCKER_CONTENT_DIGEST, parameters.digest.to_string())
                    .header(ACCEPT_RANGES, "bytes")
                    .header(CONTENT_LENGTH, length.to_string())
                    .header(CONTENT_RANGE, range)
                    .body(Body::streaming(stream))?
            }
            GetBlobResponse::Reader(stream, total_length) => Response::builder()
                .status(StatusCode::OK)
                .header(DOCKER_CONTENT_DIGEST, parameters.digest.to_string())
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_LENGTH, total_length)
                .body(Body::streaming(stream))?,
            GetBlobResponse::Empty => Response::builder()
                .status(StatusCode::OK)
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_LENGTH, 0)
                .body(Body::empty())?,
        };

        Ok(res)
    }
}
