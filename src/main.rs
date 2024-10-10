#![forbid(unsafe_code)]
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::tokio::TokioIo;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use regex::Regex;
use registry::Registry;
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio::pin;
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use uuid::Uuid;
use x509_parser::prelude::{FromDer, X509Certificate};

mod config;
mod error;
mod http_helpers;
mod io_helpers;
mod oci;
mod policy;
mod registry;
mod storage;
mod tls;

use crate::config::Config;
use crate::error::RegistryError;
use crate::http_helpers::{
    paginated_response, parse_authorization_header, parse_query_parameters, parse_range_header,
};
use crate::io_helpers::parse_regex;
use crate::oci::{Digest, Reference, ReferrerList};
use crate::policy::{ClientAction, ClientIdentity};
use crate::registry::{BlobData, NewUpload};
use crate::storage::{DiskStorageEngine, StorageEngine};
use crate::tls::{build_root_store, load_certificate_bundle, load_private_key};

lazy_static! {
    static ref ROUTE_API_VERSION_REGEX: Regex = Regex::new(r"^/v2/?$").unwrap();
    static ref ROUTE_UPLOADS_REGEX: Regex =
        Regex::new(r"^/v2/(?P<name>.+)/blobs/uploads/?$").unwrap();
    static ref ROUTE_UPLOAD_REGEX: Regex =
        Regex::new(r"^/v2/(?P<name>.+)/blobs/uploads/(?P<uuid>[0-9a-fA-F-]+)$").unwrap();
    static ref ROUTE_BLOB_REGEX: Regex =
        Regex::new(r"^/v2/(?P<name>.+)/blobs/(?P<digest>.+)$").unwrap();
    static ref ROUTE_MANIFEST_REGEX: Regex =
        Regex::new(r"^/v2/(?P<name>.+)/manifests/(?P<reference>.+)$").unwrap();
    static ref ROUTE_REFERRERS_REGEX: Regex =
        Regex::new(r"^/v2/(?P<name>.+)/referrers/(?P<digest>.+)$").unwrap();
    static ref ROUTE_LIST_TAGS_REGEX: Regex = Regex::new(r"^/v2/(?P<name>.+)/tags/list$").unwrap();
    static ref ROUTE_CATALOG_REGEX: Regex = Regex::new(r"^/v2/_catalog$").unwrap();
}

#[derive(Deserialize)]
pub struct NewUploadParameters {
    pub name: String,
}

#[derive(Deserialize)]
pub struct UploadParameters {
    pub name: String,
    pub uuid: Uuid,
}

#[derive(Deserialize)]
pub struct ManifestParameters {
    pub name: String,
    pub reference: Reference,
}

#[derive(Deserialize)]
pub struct ReferrerParameters {
    pub name: String,
    pub digest: Digest,
}

#[derive(Deserialize)]
pub struct TagsParameters {
    pub name: String,
}

#[derive(Deserialize)]
pub struct BlobParameters {
    pub name: String,
    pub digest: Digest,
}

type BytesFrameStream = Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, io::Error>> + Send>>;

pub enum RegistryResponseBody {
    Empty(Empty<Bytes>),
    Fixed(Full<Bytes>),
    Streaming(StreamBody<BytesFrameStream>),
}

impl RegistryResponseBody {
    pub fn empty() -> Self {
        RegistryResponseBody::Empty(Empty::new())
    }

    pub fn fixed(data: Vec<u8>) -> Self {
        let data = Bytes::from(data);
        RegistryResponseBody::Fixed(Full::new(data))
    }

    pub fn streaming<R>(reader: R) -> Self
    where
        R: AsyncRead + Send + 'static,
    {
        let stream = ReaderStream::new(reader).map(|result| result.map(Frame::data));
        RegistryResponseBody::Streaming(StreamBody::new(Box::pin(stream)))
    }
}

impl Body for RegistryResponseBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            RegistryResponseBody::Empty(body) => Pin::new(body)
                .poll_frame(cx)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            RegistryResponseBody::Fixed(body) => Pin::new(body)
                .poll_frame(cx)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            RegistryResponseBody::Streaming(body) => Pin::new(body).poll_frame(cx),
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let config = match Config::load("config.toml").await {
        Ok(config) => Box::leak(Box::new(config)),
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid configuration",
            ));
        }
    };

    let address = config.server.bind_address.parse::<IpAddr>().map_err(|e| {
        error!("Failed to parse bind address: {}", e);
        io::Error::new(io::ErrorKind::InvalidInput, "Invalid bind address")
    })?;

    let binding_addr = SocketAddr::new(address, config.server.port);

    let tls_acceptor;
    if let Some(tls) = &config.server.tls {
        info!("Detected TLS configuration");
        let server_certs = load_certificate_bundle(&tls.server_certificate_bundle)?;
        let server_key = load_private_key(&tls.server_private_key)?;

        let config = match &tls.client_ca_bundle {
            Some(client_ca_bundle) => {
                let client_cert = load_certificate_bundle(client_ca_bundle)?;
                let client_cert_store = build_root_store(client_cert)?;

                let client_cert_verifier =
                    WebPkiClientVerifier::builder(Arc::new(client_cert_store))
                        .allow_unauthenticated()
                        .build()
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

                rustls::ServerConfig::builder()
                    .with_client_cert_verifier(client_cert_verifier)
                    .with_single_cert(server_certs, server_key)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
            }
            None => rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(server_certs, server_key)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?,
        };

        tls_acceptor = Some(TlsAcceptor::from(Arc::new(config)));
    } else {
        info!("No TLS configuration detected (will serve over insecure HTTP)");
        tls_acceptor = None;
    }

    info!("Initializing registry");
    // TODO: new() or from_config()
    let registry = Arc::new(Registry {
        storage: DiskStorageEngine::new(config.storage.root_dir.clone()),
        credentials: config.build_credentials(),
        namespaces: config.build_namespace_list(),
        namespace_default_allow: config.build_namespace_default_allow_list(),
        namespace_policies: config
            .build_namespace_policies()
            .expect("Failed to build policy rules"),
    });

    info!("Starting registry server on {}", binding_addr);
    let listener = TcpListener::bind(binding_addr).await?;

    info!("Listening on: {}", binding_addr);

    // Use a 5 second timeout for incoming connections to the server.
    // If a request is in progress when the 5 second timeout elapses,
    // use a 2 second timeout for processing the final request and graceful shutdown.
    // TODO: Make these configurable
    let timeouts = vec![Duration::from_secs(5), Duration::from_secs(2)];

    match tls_acceptor {
        Some(tls_acceptor) => serve_tls(listener, tls_acceptor, timeouts, registry).await,
        None => serve_insecure(listener, timeouts, registry).await,
    }
}

async fn serve_tls<T>(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    timeouts: Vec<Duration>,
    registry: Arc<Registry<T>>,
) -> io::Result<()>
where
    T: StorageEngine + Send + Sync + 'static,
{
    loop {
        let registry = registry.clone();
        let timeouts = timeouts.clone();

        debug!("Waiting for incoming connection");
        let (tcp, remote_address) = listener.accept().await?;

        if let Ok(tls) = tls_acceptor.accept(tcp).await {
            let (_, session) = tls.get_ref();
            let client_identity = session
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| {
                    // parse cert with x509-parser and isolate the O and OU fields from the certificate
                    match X509Certificate::from_der(cert.as_ref()).ok() {
                        Some((_, cert)) => ClientIdentity::from_cert(&cert).ok(),
                        None => None,
                    }
                });

            debug!(
                "Client Identity from peer certificate: {:?}",
                client_identity
            );

            debug!("Accepted connection from {:?}", remote_address);
            let io = TokioIo::new(tls);

            serve_request(registry, timeouts, io, client_identity.unwrap_or_default());
        }
    }
}

async fn serve_insecure<T>(
    listener: TcpListener,
    timeouts: Vec<Duration>,
    registry: Arc<Registry<T>>,
) -> io::Result<()>
where
    T: StorageEngine + Send + Sync + 'static,
{
    loop {
        let registry = registry.clone();
        let timeouts = timeouts.clone();

        debug!("Waiting for incoming connection");
        let (tcp, remote_address) = listener.accept().await?;

        debug!("Accepted connection from {:?}", remote_address);
        let io = TokioIo::new(tcp);

        serve_request(registry, timeouts, io, ClientIdentity::new());
    }
}

fn serve_request<T, S>(
    registry: Arc<Registry<T>>,
    timeouts: Vec<Duration>,
    io: TokioIo<S>,
    client_identity: ClientIdentity,
) where
    T: StorageEngine + Send + Sync + 'static,
    S: Unpin + AsyncWrite + AsyncRead + Send + 'static,
{
    tokio::task::spawn(async move {
        let registry = registry.clone();
        let client_identity = client_identity.clone();

        let conn = http1::Builder::new().serve_connection(
            io,
            service_fn(move |req| {
                let registry = registry.clone();
                let client_identity = client_identity.clone();

                async move {
                    match router::<T>(req, registry, client_identity).await {
                        Ok(res) => Ok::<Response<RegistryResponseBody>, Infallible>(res),
                        Err(e) => Ok(e.to_response()),
                    }
                }
            }),
        );
        pin!(conn);

        // Iterate the timeouts.  Use tokio::select! to wait on the
        // result of polling the connection itself,
        // and also on tokio::time::sleep for the current timeout duration.
        for (iter, sleep_duration) in timeouts.iter().enumerate() {
            debug!("iter = {} sleep_duration = {:?}", iter, sleep_duration);
            tokio::select! {
                res = conn.as_mut() => {
                    // Polling the connection returned a result.
                    // In this case print either the successful or error result for the connection
                    // and break out of the loop.
                    match res {
                        Ok(()) => debug!("after polling conn, no error"),
                        Err(e) =>  debug!("error serving connection: {:?}", e),
                    };
                    break;
                }
                _ = tokio::time::sleep(*sleep_duration) => {
                    // tokio::time::sleep returned a result.
                    // Call graceful_shutdown on the connection and continue the loop.
                    debug!("iter = {} got timeout_interval, calling conn.graceful_shutdown", iter);
                    conn.as_mut().graceful_shutdown();
                }
            }
        }
    });
}

async fn router<T>(
    req: Request<Incoming>,
    registry: Arc<Registry<T>>,
    mut client_identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync + 'static,
{
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let basic_auth_credentials = req
        .headers()
        .get("Authorization")
        .and_then(parse_authorization_header);

    debug!("Authorization: {:?}", basic_auth_credentials);

    if let Some((username, password)) = basic_auth_credentials {
        client_identity.set_credentials(username, password);
    }

    if ROUTE_API_VERSION_REGEX.is_match(&path) {
        if method == Method::GET {
            info!("API version check: {}", path);
            return handle_get_api_version(registry, client_identity).await;
        }
    } else if let Some(parameters) = parse_regex::<NewUploadParameters>(&path, &ROUTE_UPLOADS_REGEX)
    {
        if method == Method::POST {
            info!("Start upload: {}", path);
            return handle_start_upload(req, registry, client_identity, parameters).await;
        }
    } else if let Some(parameters) = parse_regex::<UploadParameters>(&path, &ROUTE_UPLOAD_REGEX) {
        if method == Method::GET {
            info!("Get upload progress: {}", path);
            return handle_get_upload_progress(registry, client_identity, parameters).await;
        }
        if method == Method::PATCH {
            info!("Patch upload: {}", path);
            return handle_patch_upload(req, registry, client_identity, parameters).await;
        }
        if method == Method::PUT {
            info!("Put upload: {}", path);
            return handle_put_upload(req, registry, client_identity, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete upload: {}", path);
            return handle_delete_upload(registry, client_identity, parameters).await;
        }
    } else if let Some(parameters) = parse_regex::<BlobParameters>(&path, &ROUTE_BLOB_REGEX) {
        if method == Method::GET {
            info!("Get blob: {}", path);
            return handle_get_blob(req, registry, client_identity, parameters).await;
        }
        if method == Method::HEAD {
            info!("Head blob: {}", path);
            return handle_head_blob(registry, client_identity, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete blob: {}", path);
            return handle_delete_blob(registry, client_identity, parameters).await;
        }
    } else if let Some(parameters) = parse_regex::<ManifestParameters>(&path, &ROUTE_MANIFEST_REGEX)
    {
        if method == Method::GET {
            info!("Get manifest: {}", path);
            return handle_get_manifest(registry, client_identity, parameters).await;
        }
        if method == Method::HEAD {
            info!("Head manifest: {}", path);
            return handle_head_manifest(registry, client_identity, parameters).await;
        }
        if method == Method::PUT {
            info!("Put manifest: {}", path);
            return handle_put_manifest(req, registry, client_identity, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete manifest: {}", path);
            return handle_delete_manifest(registry, client_identity, parameters).await;
        }
    } else if let Some(parameters) =
        parse_regex::<ReferrerParameters>(&path, &ROUTE_REFERRERS_REGEX)
    {
        if method == Method::GET {
            info!("Get referrers: {}", path);
            return handle_get_referrers(registry, client_identity, parameters).await;
        }
    } else if ROUTE_CATALOG_REGEX.is_match(&path) {
        if method == Method::GET {
            info!("List catalog: {}", path);
            return handle_list_catalog(req, registry, client_identity).await;
        }
    } else if let Some(parameters) = parse_regex::<TagsParameters>(&path, &ROUTE_LIST_TAGS_REGEX) {
        if method == Method::GET {
            info!("List tags: {}", path);
            return handle_list_tags(req, registry, client_identity, parameters).await;
        }
    }

    warn!("Not found: {}", path);
    Err(RegistryError::NotFound)
}

async fn handle_get_api_version<T>(
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine,
{
    client_identity.can_do(&registry, ClientAction::GetApiVersion)?;

    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_get_manifest<T>(
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(
        &registry,
        ClientAction::GetManifest(parameters.name.clone(), parameters.reference.clone()),
    )?;

    let manifest = registry
        .get_manifest(&parameters.name, parameters.reference.into())
        .await?;

    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", manifest.media_type)
        .header("Docker-Content-Digest", manifest.digest.to_string())
        .body(RegistryResponseBody::fixed(manifest.content))?;

    Ok(res)
}

async fn handle_head_manifest<T>(
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(
        &registry,
        ClientAction::GetManifest(parameters.name.clone(), parameters.reference.clone()),
    )?;

    let manifest = registry
        .head_manifest(&parameters.name, parameters.reference.into())
        .await?;

    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", manifest.media_type)
        .header("Docker-Content-Digest", manifest.digest.to_string())
        .header("Content-Length", manifest.size)
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_get_blob<T>(
    req: Request<Incoming>,
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(
        &registry,
        ClientAction::GetBlob(parameters.name.clone(), parameters.digest.clone()),
    )?;

    let range_header = req.headers().get("range");
    let range = range_header.map(parse_range_header).transpose()?;

    let res = match registry
        .get_blob(&parameters.name, &parameters.digest, range)
        .await?
    {
        BlobData::RangedReader(reader, (start, end), total_length) => {
            let length = end - start + 1;
            let stream = reader.take(length);
            let range = format!("bytes {}-{}/{}", start, end, total_length);

            Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header("Docker-Content-Digest", parameters.digest.to_string())
                .header("Accept-Ranges", "bytes")
                .header("Content-Length", length.to_string())
                .header("Content-Range", range)
                .body(RegistryResponseBody::streaming(stream))?
        }
        BlobData::Reader(stream, total_length) => Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Content-Digest", parameters.digest.to_string())
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", total_length.to_string())
            .body(RegistryResponseBody::streaming(stream))?,
        BlobData::Empty => Response::builder()
            .status(StatusCode::OK)
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", "0")
            .body(RegistryResponseBody::empty())?,
    };

    Ok(res)
}

async fn handle_head_blob<T>(
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(
        &registry,
        ClientAction::GetBlob(parameters.name.clone(), parameters.digest.clone()),
    )?;

    let blob = registry
        .head_blob(&parameters.name, parameters.digest)
        .await?;
    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", blob.digest.to_string())
        .header("Content-Length", blob.size.to_string())
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_start_upload<T>(
    request: Request<Incoming>,
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: NewUploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(&registry, ClientAction::PutBlob(parameters.name.clone()))?;

    #[derive(Deserialize, Default)]
    struct UploadQuery {
        digest: Option<String>,
    }

    let query: UploadQuery = parse_query_parameters(request.uri().query())?;
    let digest = query.digest.map(|s| Digest::from_str(&s)).transpose()?;

    let res = match registry.start_upload(&parameters.name, digest).await? {
        NewUpload::ExistingBlob(digest) => Response::builder()
            .status(StatusCode::CREATED)
            .header(
                "Location",
                format!("/v2/{}/blobs/{}", parameters.name, digest),
            )
            .header("Docker-Content-Digest", digest.to_string())
            .body(RegistryResponseBody::empty())?,
        NewUpload::Session(location, session_uuid) => Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("Location", location)
            .header("Range", "0-0")
            .header("Docker-Upload-UUID", session_uuid.to_string())
            .body(RegistryResponseBody::empty())?,
    };

    Ok(res)
}

async fn handle_patch_upload<T>(
    request: Request<Incoming>,
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(&registry, ClientAction::PutBlob(parameters.name.clone()))?;

    let range = request
        .headers()
        .get("content-range")
        .map(parse_range_header)
        .transpose()?;
    let start_offset = range.map(|(start, _)| start);

    let body = request.into_body();
    let location = format!("/v2/{}/blobs/uploads/{}", &parameters.name, parameters.uuid);

    let range_max = registry
        .patch_upload(&parameters.name, parameters.uuid, start_offset, body)
        .await?;
    let range_max = format!("0-{}", range_max);

    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Location", location)
        .header("Range", range_max)
        .header("Content-Length", "0")
        .header("Docker-Upload-UUID", parameters.uuid.to_string())
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_put_upload<T>(
    request: Request<Incoming>,
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(&registry, ClientAction::PutBlob(parameters.name.clone()))?;

    #[derive(Deserialize, Default)]
    struct CompleteUploadQuery {
        digest: String,
    }

    let query: CompleteUploadQuery = parse_query_parameters(request.uri().query())?;
    let digest = Digest::from_str(&query.digest)?;

    let body = request.into_body();
    registry
        .complete_upload(&parameters.name, parameters.uuid, digest.clone(), body)
        .await?;

    let location = format!("/v2/{}/blobs/{}", &parameters.name, digest);

    let res = Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", location)
        .header("Docker-Content-Digest", digest.to_string())
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_delete_upload<T>(
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(&registry, ClientAction::PutBlob(parameters.name.clone()))?;

    registry
        .delete_upload(&parameters.name, parameters.uuid)
        .await?;

    let res = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_get_upload_progress<T>(
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(&registry, ClientAction::PutBlob(parameters.name.clone()))?;

    let location = format!("/v2/{}/blobs/uploads/{}", parameters.name, parameters.uuid);

    let range_max = registry
        .get_upload_range_max(&parameters.name, parameters.uuid)
        .await?;
    let range_max = format!("0-{}", range_max);

    let res = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Location", location)
        .header("Range", range_max)
        .header("Docker-Upload-UUID", parameters.uuid.to_string())
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_delete_blob<T>(
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(
        &registry,
        ClientAction::DeleteBlob(parameters.name.clone(), parameters.digest.clone()),
    )?;

    registry
        .delete_blob(&parameters.name, parameters.digest)
        .await?;

    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_put_manifest<T>(
    request: Request<Incoming>,
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(
        &registry,
        ClientAction::PutManifest(parameters.name.clone(), parameters.reference.clone()),
    )?;

    let content_type = request
        .headers()
        .get("Content-Type")
        .map(|h| h.to_str())
        .transpose()
        .map_err(|_| RegistryError::ManifestInvalid)?
        .ok_or(RegistryError::ManifestInvalid)?
        .to_string();

    let request_body = request
        .into_body()
        .collect()
        .await
        .map_err(|_| RegistryError::ManifestInvalid)?;
    let body = request_body.to_bytes();

    let manifest = registry
        .put_manifest(
            &parameters.name,
            parameters.reference.clone(),
            content_type,
            &body,
        )
        .await?;
    let location = format!("/v2/{}/manifests/{}", parameters.name, parameters.reference);

    let res = match manifest.subject {
        Some(subject) => Response::builder()
            .status(StatusCode::CREATED)
            .header("Location", location)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .header("OCI-Subject", subject.to_string())
            .body(RegistryResponseBody::empty())?,
        None => Response::builder()
            .status(StatusCode::CREATED)
            .header("Location", location)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .body(RegistryResponseBody::empty())?,
    };

    Ok(res)
}

async fn handle_delete_manifest<T>(
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(
        &registry,
        ClientAction::DeleteManifest(parameters.name.clone(), parameters.reference.clone()),
    )?;

    registry
        .delete_manifest(&parameters.name, parameters.reference)
        .await?;

    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_get_referrers<T>(
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: ReferrerParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(
        &registry,
        ClientAction::GetReferrers(parameters.name.clone(), parameters.digest.clone()),
    )?;

    // TODO: support filtering!
    let manifests = registry
        .get_referrers(&parameters.name, parameters.digest)
        .await?;

    let referrer_list = ReferrerList {
        manifests,
        ..ReferrerList::default()
    };
    let referrer_list = serde_json::to_string(&referrer_list)?;
    let referrer_list = referrer_list.into_bytes();

    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/vnd.oci.image.index.v1+json")
        .body(RegistryResponseBody::fixed(referrer_list))?;

    Ok(res)
}

async fn handle_list_catalog<T>(
    request: Request<Incoming>,
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(&registry, ClientAction::ListCatalog)?;

    #[derive(Debug, Deserialize, Default)]
    struct CatalogQuery {
        n: Option<u32>,
        last: Option<String>,
    }

    #[derive(Serialize, Debug)]
    struct CatalogResponse {
        repositories: Vec<String>,
    }

    let query: CatalogQuery = parse_query_parameters(request.uri().query())?;

    let (repositories, link) = registry.list_catalog(query.n, query.last).await?;

    let catalog = CatalogResponse { repositories };
    let catalog = serde_json::to_string(&catalog)?;

    paginated_response(catalog, link)
}

async fn handle_list_tags<T>(
    request: Request<Incoming>,
    registry: Arc<Registry<T>>,
    client_identity: ClientIdentity,
    parameters: TagsParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    client_identity.can_do(&registry, ClientAction::ListTags(parameters.name.clone()))?;

    #[derive(Deserialize, Debug, Default)]
    struct TagsQuery {
        n: Option<u32>,
        last: Option<String>,
    }

    #[derive(Serialize, Debug)]
    struct TagsResponse {
        name: String,
        tags: Vec<String>,
    }

    let query: TagsQuery = parse_query_parameters(request.uri().query())?;

    let (tags, link) = registry
        .list_tags(&parameters.name, query.n, query.last)
        .await?;

    let tag_list = TagsResponse {
        name: parameters.name.to_string(),
        tags,
    };
    let tag_list = serde_json::to_string(&tag_list)?;

    paginated_response(tag_list, link)
}
