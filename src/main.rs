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
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpListener;
use tokio::pin;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

mod config;
mod error;
mod http_helpers;
mod io_helpers;
mod oci;
mod registry;
mod storage;

use crate::config::Config;
use crate::error::RegistryError;
use crate::http_helpers::{paginated_response, parse_query_parameters, parse_range_header};
use crate::io_helpers::parse_regex;
use crate::oci::{Digest, Reference, ReferrerList};
use crate::registry::{BlobData, NewUpload};
use crate::storage::{DiskStorageEngine, StorageEngine};

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
        Regex::new(r"^/v2/(?P<name>.+)/referrers/(?P<reference>.+)$").unwrap();
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
    pub reference: Digest,
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

type BytesFrameStream = Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, std::io::Error>> + Send>>;

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
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            RegistryResponseBody::Empty(body) => Pin::new(body)
                .poll_frame(cx)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
            RegistryResponseBody::Fixed(body) => Pin::new(body)
                .poll_frame(cx)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
            RegistryResponseBody::Streaming(body) => Pin::new(body).poll_frame(cx),
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let config = match Config::load("config.toml").await {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    let registry = Registry {
        storage: DiskStorageEngine::new(config.storage.root_dir.clone()),
    };

    let registry = Arc::new(registry);

    let addr = SocketAddr::new(
        config
            .server
            .bind_address
            .parse::<IpAddr>()
            .unwrap_or_else(|e| {
                error!("Invalid bind address: {}", e);
                std::process::exit(1);
            }),
        config.server.port,
    );

    // Use a 5 second timeout for incoming connections to the server.
    // If a request is in progress when the 5 second timeout elapses,
    // use a 2 second timeout for processing the final request and graceful shutdown.
    let connection_timeouts = vec![Duration::from_secs(5), Duration::from_secs(2)];

    // Bind to the port and listen for incoming TCP connections
    let listener = TcpListener::bind(addr).await.unwrap(); // TODO: Handle errors
    info!("Listening on http://{}", addr);
    loop {
        let registry = registry.clone();

        // When an incoming TCP connection is received grab a TCP stream for
        // client<->server communication.
        let (tcp, remote_address) = listener.accept().await.unwrap(); // TODO: Handle errors

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(tcp);

        // Print the remote address connecting to our server.
        debug!("Accepted connection from {:?}", remote_address);

        // Clone the connection_timeouts so they can be passed to the new task.
        let connection_timeouts_clone = connection_timeouts.clone();

        // Spin up a new task in Tokio so we can continue to listen for new TCP connection on the
        // current task without waiting for the processing of the HTTP1 connection we just received
        // to finish
        tokio::task::spawn(async move {
            let registry = registry.clone();

            // Pin the connection object so we can use tokio::select! below.
            let conn = http1::Builder::new().serve_connection(
                io,
                service_fn(move |req| {
                    let registry = registry.clone();
                    async move {
                        match router::<DiskStorageEngine>(req, registry).await {
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
            for (iter, sleep_duration) in connection_timeouts_clone.iter().enumerate() {
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
}

async fn router<T>(
    req: Request<Incoming>,
    registry: Arc<Registry<T>>,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync + 'static,
{
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if ROUTE_API_VERSION_REGEX.is_match(&path) {
        if method == Method::GET {
            info!("API version check: {}", path);
            return handle_api_version::<T>().await;
        }
    } else if let Some(parameters) = parse_regex::<NewUploadParameters>(&path, &ROUTE_UPLOADS_REGEX)
    {
        if method == Method::POST {
            info!("Start upload: {}", path);
            return handle_start_upload(req, registry, parameters).await;
        }
    } else if let Some(parameters) = parse_regex::<UploadParameters>(&path, &ROUTE_UPLOAD_REGEX) {
        if method == Method::GET {
            info!("Get upload progress: {}", path);
            return handle_get_upload_progress(registry, parameters).await;
        }
        if method == Method::PATCH {
            info!("Patch upload: {}", path);
            return handle_patch_upload(req, registry, parameters).await;
        }
        if method == Method::PUT {
            info!("Put upload: {}", path);
            return handle_put_upload(req, registry, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete upload: {}", path);
            return handle_delete_upload(registry, parameters).await;
        }
    } else if let Some(parameters) = parse_regex::<BlobParameters>(&path, &ROUTE_BLOB_REGEX) {
        if method == Method::GET {
            info!("Get blob: {}", path);
            return handle_get_blob(req, registry, parameters).await;
        }
        if method == Method::HEAD {
            info!("Head blob: {}", path);
            return handle_head_blob(registry, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete blob: {}", path);
            return handle_delete_blob(registry, parameters).await;
        }
    } else if let Some(parameters) = parse_regex::<ManifestParameters>(&path, &ROUTE_MANIFEST_REGEX)
    {
        if method == Method::GET {
            info!("Get manifest: {}", path);
            return handle_get_manifest(registry, parameters).await;
        }
        if method == Method::HEAD {
            info!("Head manifest: {}", path);
            return handle_head_manifest(registry, parameters).await;
        }
        if method == Method::PUT {
            info!("Put manifest: {}", path);
            return handle_put_manifest(req, registry, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete manifest: {}", path);
            return handle_delete_manifest(registry, parameters).await;
        }
    } else if let Some(parameters) =
        parse_regex::<ReferrerParameters>(&path, &ROUTE_REFERRERS_REGEX)
    {
        if method == Method::GET {
            info!("Get referrers: {}", path);
            return handle_get_referrers(registry, parameters).await;
        }
    } else if ROUTE_CATALOG_REGEX.is_match(&path) {
        if method == Method::GET {
            info!("List catalog: {}", path);
            return handle_list_catalog(req, registry).await;
        }
    } else if let Some(parameters) = parse_regex::<TagsParameters>(&path, &ROUTE_LIST_TAGS_REGEX) {
        if method == Method::GET {
            info!("List tags: {}", path);
            return handle_list_tags(req, registry, parameters).await;
        }
    }

    warn!("Not found: {}", path);
    Err(RegistryError::NotFound)
}

async fn handle_api_version<T>() -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

async fn handle_get_manifest<T>(
    registry: Arc<Registry<T>>,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: NewUploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: ReferrerParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
    let manifests = registry
        .get_referrers(&parameters.name, parameters.reference)
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
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
    parameters: TagsParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError>
where
    T: StorageEngine + Send + Sync,
{
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
