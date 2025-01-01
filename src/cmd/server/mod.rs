use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;
use std::convert::Infallible;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::pin;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

mod handlers;
mod insecure_listener;
mod params;
mod tls_listener;

use crate::cmd::error::CommandError;
use crate::cmd::server::insecure_listener::InsecureListener;
use crate::cmd::server::params::deserialize_params;
use crate::cmd::server::tls_listener::TlsListener;
use crate::configuration::Configuration;
use crate::error::RegistryError;
use crate::oci::{Digest, Reference};
use crate::policy::ClientIdentity;
use crate::registry::{Registry, RegistryResponseBody};

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
    static ref RANGE_RE: Regex = Regex::new(r"^(?:bytes=)?(?P<start>\d+)-(?P<end>\d+)$").unwrap();
}

#[derive(Debug, Deserialize)]
pub struct NewUploadParameters {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UploadParameters {
    pub name: String,
    pub uuid: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct ManifestParameters {
    pub name: String,
    pub reference: Reference,
}

#[derive(Debug, Deserialize)]
pub struct ReferrerParameters {
    pub name: String,
    pub digest: Digest,
}

#[derive(Debug, Deserialize)]
pub struct TagsParameters {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct BlobParameters {
    pub name: String,
    pub digest: Digest,
}

pub enum ServiceListener {
    Insecure(InsecureListener),
    Secure(TlsListener),
}

pub struct Server {
    listener: ServiceListener,
}

impl Server {
    pub fn try_from_config(config: &Configuration) -> Result<Server, CommandError> {
        let listener = if config.server.tls.is_some() {
            ServiceListener::Secure(TlsListener::try_from_config(config)?)
        } else {
            ServiceListener::Insecure(InsecureListener::try_from_config(config)?)
        };

        Ok(Server { listener })
    }

    pub fn notify_config_change(&self, config: &Configuration) -> Result<(), CommandError> {
        match &self.listener {
            ServiceListener::Insecure(listener) => listener.notify_config_change(config)?,
            ServiceListener::Secure(listener) => listener.notify_config_change(config)?,
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<(), CommandError> {
        match &self.listener {
            ServiceListener::Insecure(listener) => listener.serve().await?,
            ServiceListener::Secure(listener) => listener.serve().await?,
        }

        Ok(())
    }
}

fn serve_request<S>(
    stream: TokioIo<S>,
    timeouts: Arc<Vec<Duration>>,
    registry: Arc<Registry>,
    identity: ClientIdentity,
) where
    S: Unpin + AsyncWrite + AsyncRead + Send + Debug + 'static,
{
    tokio::task::spawn(async move {
        let conn = http1::Builder::new().serve_connection(
            stream,
            service_fn(move |request| {
                crate::cmd::server::handle_request(registry.clone(), request, identity.clone())
            }),
        );
        pin!(conn);

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

#[instrument(skip(request))]
async fn handle_request(
    registry: Arc<Registry>,
    request: Request<Incoming>,
    identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, Infallible> {
    let start_time = std::time::Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let error_level;

    let response = match router(&registry, request, identity).await {
        Ok(res) => {
            error_level = false;
            Ok::<Response<RegistryResponseBody>, Infallible>(res)
        }
        Err(e) => {
            error_level = true;
            Ok(e.to_response_with_span_id(tracing::Span::current().id()))
        }
    };

    let elapsed = start_time.elapsed();
    let status = response
        .as_ref()
        .map(|r| r.status().to_string())
        .unwrap_or("(UNKNOWN STATUS)".to_string());

    let span_id = tracing::Span::current()
        .id()
        .as_ref()
        .map(|id| format!(" {:x}", id.into_u64()))
        .unwrap_or_default();

    if error_level {
        error!("{} {:?} {} {}{}", status, elapsed, method, path, span_id);
    } else {
        info!("{} {:?} {} {}{}", status, elapsed, method, path, span_id);
    }

    response
}

#[instrument(skip(request))]
async fn router(
    registry: &Registry,
    request: Request<Incoming>,
    mut identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let basic_auth_credentials = request
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
            return handlers::handle_get_api_version(registry, identity).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) = deserialize_params(&path, &ROUTE_UPLOADS_REGEX) {
        if method == Method::POST {
            info!("Start upload: {}", path);
            return handlers::handle_start_upload(registry, request, identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) = deserialize_params(&path, &ROUTE_UPLOAD_REGEX) {
        if method == Method::GET {
            info!("Get upload progress: {}", path);
            return handlers::handle_get_upload_progress(registry, identity, parameters).await;
        }
        if method == Method::PATCH {
            info!("Patch upload: {}", path);
            return handlers::handle_patch_upload(registry, request, identity, parameters).await;
        }
        if method == Method::PUT {
            info!("Put upload: {}", path);
            return handlers::handle_put_upload(registry, request, identity, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete upload: {}", path);
            return handlers::handle_delete_upload(registry, identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) = deserialize_params(&path, &ROUTE_BLOB_REGEX) {
        if method == Method::GET {
            info!("Get blob: {}", path);
            return handlers::handle_get_blob(registry, request, identity, parameters).await;
        }
        if method == Method::HEAD {
            info!("Head blob: {}", path);
            return handlers::handle_head_blob(registry, identity, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete blob: {}", path);
            return handlers::handle_delete_blob(registry, identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) = deserialize_params(&path, &ROUTE_MANIFEST_REGEX) {
        if method == Method::GET {
            info!("Get manifest: {}", path);
            return handlers::handle_get_manifest(registry, identity, parameters).await;
        }
        if method == Method::HEAD {
            info!("Head manifest: {}", path);
            return handlers::handle_head_manifest(registry, identity, parameters).await;
        }
        if method == Method::PUT {
            info!("Put manifest: {}", path);
            return handlers::handle_put_manifest(registry, request, identity, parameters).await;
        }
        if method == Method::DELETE {
            info!("Delete manifest: {}", path);
            return handlers::handle_delete_manifest(registry, identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    } else if let Some(parameters) = deserialize_params(&path, &ROUTE_REFERRERS_REGEX) {
        if method == Method::GET {
            info!("Get referrers: {}", path);
            return handlers::handle_get_referrers(registry, request, identity, parameters).await;
        }
    } else if ROUTE_CATALOG_REGEX.is_match(&path) {
        if method == Method::GET {
            info!("List catalog: {}", path);
            return handlers::handle_list_catalog(registry, request, identity).await;
        }
    } else if let Some(parameters) = deserialize_params(&path, &ROUTE_LIST_TAGS_REGEX) {
        if method == Method::GET {
            info!("List tags: {}", path);
            return handlers::handle_list_tags(registry, request, identity, parameters).await;
        }
        return Err(RegistryError::Unsupported);
    }

    Err(RegistryError::NotFound)
}

pub fn parse_authorization_header(header: &HeaderValue) -> Option<(String, String)> {
    let Ok(header_str) = header.to_str() else {
        debug!("Error parsing Authorization header as string");
        return None;
    };

    let parts: Vec<&str> = header_str.split_whitespace().collect();
    if parts.len() != 2 {
        debug!("Invalid Authorization header format: {}", header_str);
        return None;
    }

    if parts[0] != "Basic" {
        debug!("Invalid Authorization header type: {}", parts[0]);
        return None;
    }

    let Ok(auth_details) = BASE64_STANDARD.decode(parts[1]) else {
        debug!("Error decoding Authorization header");
        return None;
    };

    let Ok(auth_str) = String::from_utf8(auth_details) else {
        debug!("Error parsing Authorization header as UTF8 string");
        return None;
    };

    let parts: Vec<&str> = auth_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        warn!("Invalid Authorization header format: {}", auth_str);
        return None;
    }

    Some((parts[0].to_string(), parts[1].to_string()))
}
