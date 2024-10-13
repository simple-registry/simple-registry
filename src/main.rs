#![forbid(unsafe_code)]
use arc_swap::ArcSwap;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::tokio::TokioIo;
use lazy_static::lazy_static;
use log::{debug, error, info};
use notify::{recommended_watcher, Event, FsEventWatcher, RecursiveMode, Watcher};
use regex::Regex;
use registry::Registry;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio::pin;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use x509_parser::prelude::{FromDer, X509Certificate};

mod config;
mod error;
mod http;
mod io_helpers;
mod oci;
mod policy;
mod registry;
mod storage;
mod tls;

use self::http::request::{parse_authorization_header, parse_query_parameters, parse_range_header};
use self::http::response::paginated_response;
use crate::config::Config;
use crate::error::RegistryError;
use crate::http::response::RegistryResponseBody;
use crate::io_helpers::parse_regex;
use crate::oci::{Digest, Reference, ReferrerList};
use crate::policy::{ClientAction, ClientIdentity};
use crate::registry::{BlobData, NewUpload};

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

    //
    static ref CONFIG: ArcSwap<Config> = ArcSwap::new(Arc::new(Config::default()));
    static ref TLS_ACCEPTOR: ArcSwap<Option<TlsAcceptor>> = ArcSwap::new(Arc::new(None));
    static ref REGISTRY: ArcSwap<Registry> = ArcSwap::new(Arc::new(Registry::default()));
}

const CONFIG_PATH: &str = "config.toml";

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

pub fn reload_config() -> Result<(), io::Error> {
    let config = Config::load(CONFIG_PATH)?;

    REGISTRY.store(Arc::new(Registry::from_config(&config)));
    CONFIG.store(Arc::new(config));

    Ok(())
}

pub fn reload_tls() -> Result<(), io::Error> {
    let config = Config::load(CONFIG_PATH)?;

    TLS_ACCEPTOR.store(Arc::new(config.build_tls_acceptor()?));

    Ok(())
}

pub fn get_registry(
    identity: ClientIdentity,
    action: ClientAction,
) -> Result<Arc<Registry>, RegistryError> {
    let registry = REGISTRY.load().clone();
    identity.can_do(&registry, action)?;

    Ok(registry)
}

pub fn set_watcher_path(watcher: &mut FsEventWatcher, path: &str) -> io::Result<()> {
    watcher
        .watch(Path::new(path), RecursiveMode::Recursive)
        .map_err(|err| {
            error!("Failed to watch configuration file: {}", err);
            io::Error::new(io::ErrorKind::Other, err)
        })?;

    info!("Watching for changes to {}", path);
    Ok(())
}

fn config_watcher_event_handler(event: Result<Event, notify::Error>) {
    let event = event.unwrap();

    if event.kind.is_modify() {
        if let Err(err) = reload_config() {
            error!("Failed to reload configuration: {}", err);
        }
    }
}

fn tls_watcher_event_handler(event: Result<Event, notify::Error>) {
    let event = event.unwrap();

    if event.kind.is_modify() {
        if let Err(err) = reload_tls() {
            error!("Failed to reload configuration: {}", err);
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    reload_config()?;
    reload_tls()?;

    let mut config_watcher = recommended_watcher(config_watcher_event_handler).map_err(|err| {
        error!("Failed to create watcher: {}", err);
        io::Error::new(io::ErrorKind::Other, err)
    })?;

    set_watcher_path(&mut config_watcher, CONFIG_PATH)?;

    let mut tls_watcher = recommended_watcher(tls_watcher_event_handler).map_err(|err| {
        error!("Failed to create watcher: {}", err);
        io::Error::new(io::ErrorKind::Other, err)
    })?;

    if let Some(tls) = &CONFIG.load().server.tls {
        set_watcher_path(&mut tls_watcher, &tls.server_certificate_bundle)?;
        set_watcher_path(&mut tls_watcher, &tls.server_private_key)?;
        if let Some(client_ca) = &tls.client_ca_bundle {
            set_watcher_path(&mut tls_watcher, client_ca)?;
        }
    }

    if TLS_ACCEPTOR.load().is_some() {
        serve_tls().await
    } else {
        serve_insecure().await
    }
}

async fn serve_tls() -> io::Result<()> {
    let binding_addr = CONFIG.load().get_binding_address()?;
    let listener = TcpListener::bind(binding_addr).await?;
    info!("Listening on {} over TLS", binding_addr);

    loop {
        let (tcp, remote_address) = listener.accept().await?;

        let tls_acceptor = TLS_ACCEPTOR
            .load()
            .as_ref()
            .clone()
            .expect("TLS acceptor not initialized");

        if let Ok(tls) = tls_acceptor.accept(tcp).await {
            let (_, session) = tls.get_ref();
            let identity = session
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| match X509Certificate::from_der(cert.as_ref()).ok() {
                    Some((_, cert)) => ClientIdentity::from_cert(&cert).ok(),
                    None => None,
                });

            debug!("Client Identity from certificate: {:?}", identity);

            debug!("Accepted connection from {:?}", remote_address);
            let io = TokioIo::new(tls);

            serve_request(io, identity.unwrap_or_default());
        }
    }
}

async fn serve_insecure() -> io::Result<()> {
    let binding_addr = CONFIG.load().get_binding_address()?;
    let listener = TcpListener::bind(binding_addr).await?;
    info!("Listening on {} (non-TLS)", binding_addr);

    loop {
        debug!("Waiting for incoming connection");
        let (tcp, remote_address) = listener.accept().await?;

        debug!("Accepted connection from {:?}", remote_address);
        let io = TokioIo::new(tcp);

        serve_request(io, ClientIdentity::new());
    }
}

fn serve_request<S>(io: TokioIo<S>, identity: ClientIdentity)
where
    S: Unpin + AsyncWrite + AsyncRead + Send + 'static,
{
    tokio::task::spawn(async move {
        let identity = identity.clone();

        let conn = http1::Builder::new().serve_connection(
            io,
            service_fn(move |req| {
                let identity = identity.clone();

                async move {
                    match router(req, identity).await {
                        Ok(res) => Ok::<Response<RegistryResponseBody>, Infallible>(res),
                        Err(e) => Ok(e.to_response()),
                    }
                }
            }),
        );
        pin!(conn);

        for (iter, sleep_duration) in CONFIG.load().get_timeouts().iter().enumerate() {
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

async fn router(
    req: Request<Incoming>,
    mut identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let basic_auth_credentials = req
        .headers()
        .get("Authorization")
        .and_then(parse_authorization_header);

    debug!("Authorization: {:?}", basic_auth_credentials);

    if let Some((username, password)) = basic_auth_credentials {
        identity.set_credentials(username, password);
    }

    if ROUTE_API_VERSION_REGEX.is_match(&path) {
        if method == Method::GET {
            info!("API version check: {}", path);
            return handle_get_api_version(identity).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) = parse_regex::<NewUploadParameters>(&path, &ROUTE_UPLOADS_REGEX)
    {
        if method == Method::POST {
            info!("Start upload: {}", path);
            return handle_start_upload(req, identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) = parse_regex::<UploadParameters>(&path, &ROUTE_UPLOAD_REGEX) {
        if method == Method::GET {
            info!("Get upload progress: {}", path);
            return handle_get_upload_progress(identity, parameters).await;
        }
        if method == Method::PATCH {
            info!("Patch upload: {}", path);
            return handle_patch_upload(req, identity, parameters).await;
        }
        if method == Method::PUT {
            info!("Put upload: {}", path);
            return handle_put_upload(req, identity, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete upload: {}", path);
            return handle_delete_upload(identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) = parse_regex::<BlobParameters>(&path, &ROUTE_BLOB_REGEX) {
        if method == Method::GET {
            info!("Get blob: {}", path);
            return handle_get_blob(req, identity, parameters).await;
        }
        if method == Method::HEAD {
            info!("Head blob: {}", path);
            return handle_head_blob(identity, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete blob: {}", path);
            return handle_delete_blob(identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) = parse_regex::<ManifestParameters>(&path, &ROUTE_MANIFEST_REGEX)
    {
        if method == Method::GET {
            info!("Get manifest: {}", path);
            return handle_get_manifest(identity, parameters).await;
        }
        if method == Method::HEAD {
            info!("Head manifest: {}", path);
            return handle_head_manifest(identity, parameters).await;
        }
        if method == Method::PUT {
            info!("Put manifest: {}", path);
            return handle_put_manifest(req, identity, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete manifest: {}", path);
            return handle_delete_manifest(identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) =
        parse_regex::<ReferrerParameters>(&path, &ROUTE_REFERRERS_REGEX)
    {
        if method == Method::GET {
            info!("Get referrers: {}", path);
            return handle_get_referrers(req, identity, parameters).await;
        }
    } else if ROUTE_CATALOG_REGEX.is_match(&path) {
        if method == Method::GET {
            info!("List catalog: {}", path);
            return handle_list_catalog(req, identity).await;
        }
    } else if let Some(parameters) = parse_regex::<TagsParameters>(&path, &ROUTE_LIST_TAGS_REGEX) {
        if method == Method::GET {
            info!("List tags: {}", path);
            return handle_list_tags(req, identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    }

    Err(RegistryError::NotFound)
}

async fn handle_get_api_version(
    identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let _ = get_registry(identity, ClientAction::GetApiVersion)?;

    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_get_manifest(
    identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(
        identity,
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

async fn handle_head_manifest(
    identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(
        identity,
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

async fn handle_get_blob(
    req: Request<Incoming>,
    identity: ClientIdentity,
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(
        identity,
        ClientAction::GetBlob(parameters.name.clone(), parameters.digest.clone()),
    )?;

    let range = req
        .headers()
        .get("range")
        .map(parse_range_header)
        .transpose()?;

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

async fn handle_head_blob(
    identity: ClientIdentity,
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(
        identity,
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

async fn handle_start_upload(
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: NewUploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(identity, ClientAction::PutBlob(parameters.name.clone()))?;

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

async fn handle_patch_upload(
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(identity, ClientAction::PutBlob(parameters.name.clone()))?;

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

async fn handle_put_upload(
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(identity, ClientAction::PutBlob(parameters.name.clone()))?;

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

async fn handle_delete_upload(
    identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(identity, ClientAction::PutBlob(parameters.name.clone()))?;

    registry
        .delete_upload(&parameters.name, parameters.uuid)
        .await?;

    let res = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_get_upload_progress(
    identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(identity, ClientAction::PutBlob(parameters.name.clone()))?;

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

async fn handle_delete_blob(
    identity: ClientIdentity,
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(
        identity,
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

async fn handle_put_manifest(
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(
        identity,
        ClientAction::PutManifest(parameters.name.clone(), parameters.reference.clone()),
    )?;

    let content_type = request
        .headers()
        .get("Content-Type")
        .map(|h| h.to_str())
        .transpose()
        .map_err(|_| {
            RegistryError::ManifestInvalid(Some(
                "Unable to parse provided Content-Type header".to_string(),
            ))
        })?
        .ok_or(RegistryError::ManifestInvalid(Some(
            "No Content-Type header provided".to_string(),
        )))?
        .to_string();

    let request_body = request.into_body().collect().await.map_err(|_| {
        RegistryError::ManifestInvalid(Some(
            "Unable to retrieve manifest from client query".to_string(),
        ))
    })?;
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

async fn handle_delete_manifest(
    identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(
        identity,
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

async fn handle_get_referrers(
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: ReferrerParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(
        identity,
        ClientAction::GetReferrers(parameters.name.clone(), parameters.digest.clone()),
    )?;

    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase")]
    struct GetReferrersQuery {
        artifact_type: Option<String>,
    }

    let query: GetReferrersQuery = parse_query_parameters(request.uri().query())?;

    let manifests = registry
        .get_referrers(
            &parameters.name,
            parameters.digest,
            query.artifact_type.clone(),
        )
        .await?;

    let referrer_list = ReferrerList {
        manifests,
        ..ReferrerList::default()
    };
    let referrer_list = serde_json::to_string(&referrer_list)?.into_bytes();

    let res = match query.artifact_type {
        Some(_) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/vnd.oci.image.index.v1+json")
            .header("OCI-Filters-Applied", "artifactType")
            .body(RegistryResponseBody::fixed(referrer_list))?,
        None => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/vnd.oci.image.index.v1+json")
            .body(RegistryResponseBody::fixed(referrer_list))?,
    };

    Ok(res)
}

async fn handle_list_catalog(
    request: Request<Incoming>,
    identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(identity, ClientAction::ListCatalog)?;

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

async fn handle_list_tags(
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: TagsParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let registry = get_registry(identity, ClientAction::ListTags(parameters.name.clone()))?;

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
