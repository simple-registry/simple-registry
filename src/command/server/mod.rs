use crate::{command, configuration, registry};
use argh::FromArgs;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, ACCEPT};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::pin;
use tracing::{debug, error, info, instrument};
use uuid::Uuid;

mod handlers;
mod insecure_listener;
mod params;
mod response;
mod server_context;
mod tls_listener;

use crate::command::server::insecure_listener::InsecureListener;
use crate::command::server::params::deserialize;
use crate::command::server::response::Body;
use crate::command::server::server_context::ServerContext;
use crate::command::server::tls_listener::TlsListener;
use crate::configuration::{IdentityConfig, ServerConfig};
use crate::policy::{ClientIdentity, ClientRequest};
use crate::registry::oci_types::{Digest, Reference};
use crate::registry::Registry;

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

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "server",
    description = "Run the registry listeners"
)]
pub struct Options {}

pub struct Command {
    listener: ServiceListener,
}

impl Command {
    pub fn new(
        server_config: &ServerConfig,
        identities: &HashMap<String, IdentityConfig>,
        registry: Registry,
    ) -> Result<Command, configuration::Error> {
        let timeouts = vec![
            Duration::from_secs(server_config.query_timeout),
            Duration::from_secs(server_config.query_timeout_grace_period),
        ];
        let context = ServerContext::new(identities, timeouts, registry);

        let listener = if server_config.tls.is_some() {
            ServiceListener::Secure(TlsListener::new(server_config, context)?)
        } else {
            ServiceListener::Insecure(InsecureListener::new(server_config, context))
        };

        Ok(Command { listener })
    }

    pub fn notify_config_change(
        &self,
        server_config: ServerConfig,
        identities: &HashMap<String, IdentityConfig>,
        registry: Registry,
    ) -> Result<(), configuration::Error> {
        let timeouts = vec![
            Duration::from_secs(server_config.query_timeout),
            Duration::from_secs(server_config.query_timeout_grace_period),
        ];
        let context = ServerContext::new(identities, timeouts, registry);

        match &self.listener {
            ServiceListener::Insecure(listener) => listener.notify_config_change(context),
            ServiceListener::Secure(listener) => {
                listener.notify_config_change(server_config, context)?;
            }
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<(), command::Error> {
        match &self.listener {
            ServiceListener::Insecure(listener) => listener.serve().await?,
            ServiceListener::Secure(listener) => listener.serve().await?,
        }

        Ok(())
    }
}

async fn serve_request<S>(stream: TokioIo<S>, context: Arc<ServerContext>, identity: ClientIdentity)
where
    S: Unpin + AsyncWrite + AsyncRead + Send + Debug + 'static,
{
    let conn = http1::Builder::new().serve_connection(
        stream,
        service_fn(|request| handle_request(context.clone(), request, identity.clone())),
    );
    pin!(conn);

    for (iter, sleep_duration) in context.timeouts.iter().enumerate() {
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
            () = tokio::time::sleep(*sleep_duration) => {
                // tokio::time::sleep returned a result.
                // Call graceful_shutdown on the connection and continue the loop.
                debug!("iter = {} got timeout_interval, calling conn.graceful_shutdown", iter);
                conn.as_mut().graceful_shutdown();
            }
        }
    }
}

#[instrument(skip(context, request))]
async fn handle_request(
    context: Arc<ServerContext>,
    request: Request<Incoming>,
    identity: ClientIdentity,
) -> Result<Response<Body>, Infallible> {
    let start_time = std::time::Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let error_level;

    let response = match router(context, request, identity).await {
        Ok(res) => {
            error_level = false;
            Ok::<Response<Body>, Infallible>(res)
        }
        Err(error) => {
            error_level = true;
            if let Some(trace_id) = tracing::Span::current().id().as_ref() {
                let span_id = format!("{trace_id:?}");
                Ok(registry_error_to_response_raw(
                    &error,
                    json!({
                        "span_id": span_id
                    }),
                ))
            } else {
                Ok(registry_error_to_response_raw(&error, None::<String>))
            }
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

pub fn registry_error_to_response_raw<T>(error: &registry::Error, details: T) -> Response<Body>
where
    T: Serialize,
{
    let (status, code) = match error {
        registry::Error::BlobUnknown => (StatusCode::NOT_FOUND, "BLOB_UNKNOWN"),
        //RegistryError::BlobUploadInvalid => (StatusCode::BAD_REQUEST, "BLOB_UPLOAD_INVALID"),
        registry::Error::BlobUploadUnknown => (StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN"),
        registry::Error::DigestInvalid => (StatusCode::BAD_REQUEST, "DIGEST_INVALID"),
        registry::Error::ManifestBlobUnknown => (StatusCode::NOT_FOUND, "MANIFEST_BLOB_UNKNOWN"),
        registry::Error::ManifestInvalid(_) => (StatusCode::BAD_REQUEST, "MANIFEST_INVALID"),
        registry::Error::ManifestUnknown => (StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN"),
        registry::Error::NameInvalid => (StatusCode::BAD_REQUEST, "NAME_INVALID"),
        registry::Error::NameUnknown => (StatusCode::NOT_FOUND, "NAME_UNKNOWN"),
        //RegistryError::SizeInvalid => (StatusCode::BAD_REQUEST, "SIZE_INVALID"),
        registry::Error::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
        //RegistryError::Denied => (StatusCode::FORBIDDEN, "DENIED"),
        registry::Error::Unsupported => (StatusCode::BAD_REQUEST, "UNSUPPORTED"),
        //RegistryError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "TOOMANYREQUESTS"),
        // Convenience
        registry::Error::RangeNotSatisfiable => (StatusCode::RANGE_NOT_SATISFIABLE, "SIZE_INVALID"), // Can't find a better code from the OCI spec
        // Catch-all
        registry::Error::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        registry::Error::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR")
        }
    };

    let body = json!({
        "errors": [{
            "code": code,
            "message": error.to_string(),
            "detail": details
        }]
    });

    let body = body.to_string();
    let body = Bytes::from(body);

    match error {
        registry::Error::Unauthorized(_) => {
            let basic_realm = format!("Basic realm=\"{}\", charset=\"UTF-8\"", "Docker Registry");

            Response::builder()
                .status(status)
                .header("Content-Type", "application/json")
                .header("WWW-Authenticate", basic_realm)
                .body(Body::Fixed(Full::new(body)))
                .unwrap()
        }
        _ => Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::Fixed(Full::new(body)))
            .unwrap(),
    }
}

#[instrument(skip(context, request))]
async fn router(
    context: Arc<ServerContext>,
    request: Request<Incoming>,
    mut identity: ClientIdentity,
) -> Result<Response<Body>, registry::Error> {
    let path = request.uri().path().to_string();

    let basic_auth_credentials = request
        .headers()
        .get("Authorization")
        .and_then(parse_authorization_header);

    debug!("Authorization: {:?}", basic_auth_credentials);

    let identity = match basic_auth_credentials {
        Some((username, password)) => {
            let identity_id = context.validate_credentials(&username, &password)?;
            identity.username = Some(username);
            identity.id = identity_id;
            identity
        }
        None => identity,
    };

    if ROUTE_API_VERSION_REGEX.is_match(&path) {
        match *request.method() {
            Method::GET => {
                context.validate_request(ClientRequest::get_api_version(), identity)?;
                handlers::handle_get_api_version().await
            }
            _ => Err(registry::Error::Unsupported),
        }
    } else if let Some(parameters) = deserialize::<NewUploadParameters>(&path, &ROUTE_UPLOADS_REGEX)
    {
        match *request.method() {
            Method::POST => {
                context
                    .validate_request(ClientRequest::start_upload(&parameters.name), identity)?;
                handlers::handle_start_upload(&context.registry, request, parameters).await
            }
            _ => Err(registry::Error::Unsupported),
        }
    } else if let Some(parameters) = deserialize::<UploadParameters>(&path, &ROUTE_UPLOAD_REGEX) {
        match *request.method() {
            Method::GET => {
                context.validate_request(ClientRequest::get_upload(&parameters.name), identity)?;
                handlers::handle_get_upload_progress(&context.registry, parameters).await
            }
            Method::PATCH => {
                context
                    .validate_request(ClientRequest::update_upload(&parameters.name), identity)?;
                handlers::handle_patch_upload(&context.registry, request, parameters).await
            }
            Method::PUT => {
                context
                    .validate_request(ClientRequest::complete_upload(&parameters.name), identity)?;
                handlers::handle_put_upload(&context.registry, request, parameters).await
            }
            Method::DELETE => {
                context
                    .validate_request(ClientRequest::cancel_upload(&parameters.name), identity)?;
                handlers::handle_delete_upload(&context.registry, parameters).await
            }
            _ => Err(registry::Error::Unsupported),
        }
    } else if let Some(parameters) = deserialize::<BlobParameters>(&path, &ROUTE_BLOB_REGEX) {
        match *request.method() {
            Method::GET => {
                context.validate_request(
                    ClientRequest::get_blob(&parameters.name, &parameters.digest),
                    identity,
                )?;

                let accepted_mime_types = get_accepted_content_type(&request);
                handlers::handle_get_blob(
                    &context.registry,
                    request,
                    &accepted_mime_types,
                    parameters,
                )
                .await
            }
            Method::HEAD => {
                context.validate_request(
                    ClientRequest::get_blob(&parameters.name, &parameters.digest),
                    identity,
                )?;

                let accepted_mime_types = get_accepted_content_type(&request);
                handlers::handle_head_blob(&context.registry, &accepted_mime_types, parameters)
                    .await
            }
            Method::DELETE => {
                context.validate_request(
                    ClientRequest::delete_blob(&parameters.name, &parameters.digest),
                    identity,
                )?;
                handlers::handle_delete_blob(&context.registry, parameters).await
            }
            _ => Err(registry::Error::Unsupported),
        }
    } else if let Some(parameters) = deserialize::<ManifestParameters>(&path, &ROUTE_MANIFEST_REGEX)
    {
        match *request.method() {
            Method::GET => {
                context.validate_request(
                    ClientRequest::get_manifest(&parameters.name, &parameters.reference),
                    identity,
                )?;

                let accepted_mime_types = get_accepted_content_type(&request);
                handlers::handle_get_manifest(&context.registry, &accepted_mime_types, parameters)
                    .await
            }
            Method::HEAD => {
                context.validate_request(
                    ClientRequest::get_manifest(&parameters.name, &parameters.reference),
                    identity,
                )?;

                let accepted_mime_types = get_accepted_content_type(&request);
                handlers::handle_head_manifest(&context.registry, &accepted_mime_types, parameters)
                    .await
            }
            Method::PUT => {
                context.validate_request(
                    ClientRequest::put_manifest(&parameters.name, &parameters.reference),
                    identity,
                )?;
                handlers::handle_put_manifest(&context.registry, request, parameters).await
            }
            Method::DELETE => {
                context.validate_request(
                    ClientRequest::delete_manifest(&parameters.name, &parameters.reference),
                    identity,
                )?;
                handlers::handle_delete_manifest(&context.registry, parameters).await
            }
            _ => Err(registry::Error::Unsupported),
        }
    } else if let Some(parameters) =
        deserialize::<ReferrerParameters>(&path, &ROUTE_REFERRERS_REGEX)
    {
        match *request.method() {
            Method::GET => {
                context.validate_request(
                    ClientRequest::get_referrers(&parameters.name, &parameters.digest),
                    identity,
                )?;
                handlers::handle_get_referrers(&context.registry, request, parameters).await
            }
            _ => Err(registry::Error::Unsupported),
        }
    } else if ROUTE_CATALOG_REGEX.is_match(&path) {
        match *request.method() {
            Method::GET => {
                context.validate_request(ClientRequest::list_catalog(), identity)?;
                handlers::handle_list_catalog(&context.registry, request).await
            }
            _ => Err(registry::Error::Unsupported),
        }
    } else if let Some(parameters) = deserialize::<TagsParameters>(&path, &ROUTE_LIST_TAGS_REGEX) {
        match *request.method() {
            Method::GET => {
                context.validate_request(ClientRequest::list_tags(&parameters.name), identity)?;
                handlers::handle_list_tags(&context.registry, request, parameters).await
            }
            _ => Err(registry::Error::Unsupported),
        }
    } else {
        Err(registry::Error::NotFound)
    }
}

fn get_accepted_content_type<T>(request: &Request<T>) -> Vec<String> {
    request
        .headers()
        .get_all(ACCEPT)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
}

pub fn parse_authorization_header(header: &HeaderValue) -> Option<(String, String)> {
    let value = header
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|value| BASE64_STANDARD.decode(value).ok())
        .and_then(|value| String::from_utf8(value).ok())?;

    let (username, password) = value.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

#[cfg(test)]
mod test {
    use super::*;
    use hyper::HeaderMap;

    #[test]
    fn test_get_accepted_content_type() {
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_static("application/json"));
        headers.append(ACCEPT, HeaderValue::from_static("application/xml"));
        headers.append(ACCEPT, HeaderValue::from_static("text/plain"));

        let mut request = Request::builder();
        for (key, value) in headers.iter() {
            request = request.header(key, value);
        }
        let request = request.body(Body::empty()).unwrap();

        let result = get_accepted_content_type(&request);
        assert_eq!(
            result,
            vec!["application/json", "application/xml", "text/plain"]
        );
    }

    #[test]
    fn test_parse_authorization_header() {
        let header = HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA==");
        let result = parse_authorization_header(&header);
        assert_eq!(result, Some(("user".to_string(), "password".to_string())));

        let header = HeaderValue::from_static("Bearer dXNlcjpwYXNzd29yZA==");
        let result = parse_authorization_header(&header);
        assert_eq!(result, None);

        let header = HeaderValue::from_static("Basic dXNlcjpw YXNzd29yZA=");
        let result = parse_authorization_header(&header);
        assert_eq!(result, None);

        let header = HeaderValue::from_static("Basic dXNlcjpwY%%%%XNzd29yZA");
        let result = parse_authorization_header(&header);
        assert_eq!(result, None);

        let header = HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA===");
        let result = parse_authorization_header(&header);
        assert_eq!(result, None);

        let header = HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA==");
        let result = parse_authorization_header(&header);
        assert_eq!(result, Some(("user".to_string(), "password".to_string())));
    }
}
