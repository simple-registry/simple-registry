use crate::{command, configuration, registry};
use argh::FromArgs;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use opentelemetry::time::now;
use opentelemetry::trace::TraceContextExt;
use opentelemetry::KeyValue;
use regex::Regex;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::pin;
use tracing::{debug, error, info, instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

mod insecure_listener;
mod server_context;
mod tls_listener;

use crate::command::server::insecure_listener::InsecureListener;
use crate::command::server::server_context::ServerContext;
use crate::command::server::tls_listener::TlsListener;
use crate::configuration::{IdentityConfig, ServerConfig};
use crate::metrics_provider::{IN_FLIGHT_REQUESTS, METRICS_PROVIDER};
use crate::registry::api::body::Body;
use crate::registry::api::hyper::deserialize_ext::DeserializeExt;
use crate::registry::api::hyper::request_ext::RequestExt;
use crate::registry::api::{
    QueryBlobParameters, QueryManifestParameters, QueryNewUploadParameters, QueryUploadParameters,
    ReferrerParameters, RegistryAPIBlobHandlersExt, RegistryAPIContentDiscoveryHandlersExt,
    RegistryAPIManifestHandlersExt, RegistryAPIUploadHandlersExt, RegistryAPIVersionHandlerExt,
    TagsParameters,
};
use crate::registry::data_store::DataStore;
use crate::registry::policy_types::ClientIdentity;
use crate::registry::Registry;

static ROUTE_HEALTHZ_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/healthz$").unwrap());
static ROUTE_METRICS_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/metrics").unwrap());
static ROUTE_API_VERSION_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/v2/?$").unwrap());
static ROUTE_UPLOADS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/v2/(?P<name>.+)/blobs/uploads/?$").unwrap());
static ROUTE_UPLOAD_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v2/(?P<name>.+)/blobs/uploads/(?P<uuid>[0-9a-fA-F-]+)$").unwrap()
});
static ROUTE_BLOB_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/v2/(?P<name>.+)/blobs/(?P<digest>.+)$").unwrap());
static ROUTE_MANIFEST_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/v2/(?P<name>.+)/manifests/(?P<reference>.+)$").unwrap());
static ROUTE_REFERRERS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/v2/(?P<name>.+)/referrers/(?P<digest>.+)$").unwrap());
static ROUTE_LIST_TAGS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/v2/(?P<name>.+)/tags/list$").unwrap());
static ROUTE_CATALOG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/v2/_catalog$").unwrap());

pub enum ServiceListener<D> {
    Insecure(InsecureListener<D>),
    Secure(TlsListener<D>),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "server",
    description = "Run the registry listeners"
)]
pub struct Options {}

pub struct Command<D> {
    listener: ServiceListener<D>,
}

impl<D: DataStore + 'static> Command<D> {
    pub fn new(
        server_config: &ServerConfig,
        identities: &HashMap<String, IdentityConfig>,
        registry: Registry<D>,
    ) -> Result<Command<D>, configuration::Error> {
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
        registry: Registry<D>,
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

async fn serve_request<D: DataStore + 'static, S>(
    stream: TokioIo<S>,
    context: Arc<ServerContext<D>>,
    identity: ClientIdentity,
) where
    S: Unpin + AsyncWrite + AsyncRead + Send + Debug + 'static,
{
    let conn = http1::Builder::new().serve_connection(
        stream,
        service_fn(|request| handle_request(context.clone(), request, identity.clone())),
    );
    pin!(conn);

    IN_FLIGHT_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    METRICS_PROVIDER.metric_http_request_in_flight.record(
        IN_FLIGHT_REQUESTS.load(std::sync::atomic::Ordering::Relaxed),
        &[],
    );

    for (iter, sleep_duration) in context.timeouts.iter().enumerate() {
        debug!("iter = {iter} sleep_duration = {sleep_duration:?}");
        tokio::select! {
            res = conn.as_mut() => {
                // Polling the connection returned a result.
                // In this case print either the successful or error result for the connection
                // and break out of the loop.
                match res {
                    Ok(()) => debug!("after polling conn, no error"),
                    Err(error) =>  debug!("error serving connection: {error}"),
                }
                break;
            }
            () = tokio::time::sleep(*sleep_duration) => {
                // tokio::time::sleep returned a result.
                // Call graceful_shutdown on the connection and continue the loop.
                debug!("iter = {iter} got timeout_interval, calling conn.graceful_shutdown");
                conn.as_mut().graceful_shutdown();
            }
        }
    }

    IN_FLIGHT_REQUESTS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    METRICS_PROVIDER.metric_http_request_in_flight.record(
        IN_FLIGHT_REQUESTS.load(std::sync::atomic::Ordering::Relaxed),
        &[],
    );
}

#[instrument(skip(context, request))]
async fn handle_request<D: DataStore + 'static>(
    context: Arc<ServerContext<D>>,
    request: Request<Incoming>,
    identity: ClientIdentity,
) -> Result<Response<Body>, Infallible> {
    let start_time = now();
    let method = request.method().to_owned();
    let path = request.uri().path().to_owned();

    let trace_id = if Span::current().context().span().span_context().is_valid() {
        Some(
            Span::current()
                .context()
                .span()
                .span_context()
                .trace_id()
                .to_string(),
        )
    } else {
        None
    };

    let (handler, response) = match router(context.clone(), request, identity).await {
        (handler, Ok(response)) => (handler, response),
        (handler, Err(error)) => {
            let details = trace_id
                .clone()
                .map(|trace_id| json!({"trace_id": trace_id}))
                .unwrap_or(json!({}));
            let response = registry_error_to_response_raw(&error, details);
            (handler, response)
        }
    };

    #[allow(clippy::cast_precision_loss)]
    let elapsed = start_time.elapsed().map_or(0.0, |d| d.as_millis() as f64);
    let status = response.status();

    let handler_all = &[
        KeyValue::new("method", method.to_string()),
        KeyValue::new("endpoint", "all"),
        KeyValue::new("status_code", status.as_u16().to_string()),
    ];

    METRICS_PROVIDER
        .metric_http_request_total
        .add(1, handler_all);
    METRICS_PROVIDER
        .metric_http_request_duration
        .record(elapsed, handler_all);
    if let Some(handler) = handler {
        let handler_specific = &[
            KeyValue::new("method", method.to_string()),
            KeyValue::new("endpoint", handler),
            KeyValue::new("status_code", status.as_u16().to_string()),
        ];

        METRICS_PROVIDER
            .metric_http_request_total
            .add(1, handler_specific);
        METRICS_PROVIDER
            .metric_http_request_duration
            .record(elapsed, handler_specific);
    }

    let log = trace_id
        .map(|trace_id| format!("{trace_id} {elapsed:?} - {status} {method} {path}"))
        .unwrap_or(format!("{elapsed:?} - {status} {method} {path}"));

    if status.is_server_error() {
        error!("{log}");
    } else {
        info!("{log}");
    }

    Ok(response)
}

#[allow(clippy::too_many_lines)]
#[instrument(skip(context, req))]
async fn router<D: DataStore + 'static>(
    context: Arc<ServerContext<D>>,
    req: Request<Incoming>,
    mut id: ClientIdentity,
) -> (
    Option<&'static str>,
    Result<Response<Body>, registry::Error>,
) {
    let path = req.uri().path().to_string();

    if let Some((username, password)) = req.provided_credentials() {
        id.id = match context.validate_credentials(&username, &password) {
            Ok(id) => id,
            Err(e) => return (None, Err(e)),
        };
        id.username = Some(username);
    }

    if ROUTE_API_VERSION_REGEX.is_match(&path) && req.method() == Method::GET {
        // TODO: make this part customizable
        if !context.credentials.is_empty() && id.username.is_none() {
            return (
                Some("api-version"),
                Err(registry::Error::Unauthorized(
                    "Access denied (requires credentials)".to_string(),
                )),
            );
        }
        return (
            Some("api-version"),
            context.registry.handle_get_api_version(id).await,
        );
    } else if let Some(params) = QueryNewUploadParameters::from_regex(&path, &ROUTE_UPLOADS_REGEX) {
        if req.method() == Method::POST {
            return (
                Some("upload"),
                context.registry.handle_start_upload(req, params, id).await,
            );
        }
    } else if let Some(params) = QueryUploadParameters::from_regex(&path, &ROUTE_UPLOAD_REGEX) {
        match *req.method() {
            Method::GET => {
                return (
                    Some("upload"),
                    context.registry.handle_get_upload(params, id).await,
                )
            }
            Method::PATCH => {
                return (
                    Some("upload"),
                    context.registry.handle_patch_upload(req, params, id).await,
                )
            }
            Method::PUT => {
                return (
                    Some("upload"),
                    context.registry.handle_put_upload(req, params, id).await,
                )
            }
            Method::DELETE => {
                return (
                    Some("upload"),
                    context.registry.handle_delete_upload(params, id).await,
                )
            }
            _ => { /* NOOP */ }
        }
    } else if let Some(params) = QueryBlobParameters::from_regex(&path, &ROUTE_BLOB_REGEX) {
        match *req.method() {
            Method::GET => {
                return (
                    Some("blob"),
                    context.registry.handle_get_blob(req, params, id).await,
                )
            }
            Method::HEAD => {
                return (
                    Some("blob"),
                    context.registry.handle_head_blob(req, params, id).await,
                )
            }
            Method::DELETE => {
                return (
                    Some("blob"),
                    context.registry.handle_delete_blob(params, id).await,
                )
            }
            _ => { /* NOOP */ }
        }
    } else if let Some(params) = QueryManifestParameters::from_regex(&path, &ROUTE_MANIFEST_REGEX) {
        match *req.method() {
            Method::GET => {
                return (
                    Some("manifest"),
                    context.registry.handle_get_manifest(req, params, id).await,
                )
            }
            Method::HEAD => {
                return (
                    Some("manifest"),
                    context.registry.handle_head_manifest(req, params, id).await,
                )
            }
            Method::PUT => {
                return (
                    Some("manifest"),
                    context.registry.handle_put_manifest(req, params, id).await,
                )
            }
            Method::DELETE => {
                return (
                    Some("manifest"),
                    context.registry.handle_delete_manifest(params, id).await,
                )
            }
            _ => { /* NOOP */ }
        }
    } else if let Some(params) = ReferrerParameters::from_regex(&path, &ROUTE_REFERRERS_REGEX) {
        if req.method() == Method::GET {
            return (
                Some("referrers"),
                context.registry.handle_get_referrers(req, params, id).await,
            );
        }
    } else if ROUTE_CATALOG_REGEX.is_match(&path) {
        if req.method() == Method::GET {
            return (
                Some("catalog"),
                context.registry.handle_list_catalog(req, id).await,
            );
        }
    } else if let Some(params) = TagsParameters::from_regex(&path, &ROUTE_LIST_TAGS_REGEX) {
        if req.method() == Method::GET {
            return (
                Some("tags"),
                context.registry.handle_list_tags(req, params, id).await,
            );
        }
    } else if ROUTE_HEALTHZ_REGEX.is_match(&path) {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::Fixed(Full::new(Bytes::from("{\"status\":\"ok\"}"))))
            .map_err(registry::Error::from);

        return (Some("healthz"), response);
    } else if ROUTE_METRICS_REGEX.is_match(&path) {
        let (content_type, metrics) = METRICS_PROVIDER.gather();

        let response = Response::builder()
            .status(200)
            .header(CONTENT_TYPE, content_type)
            .body(Body::Fixed(Full::new(Bytes::from(metrics))))
            .map_err(registry::Error::from);

        return (Some("metrics"), response);
    }

    if [Method::GET, Method::HEAD].contains(req.method()) {
        (Some("not-found"), Err(registry::Error::NotFound))
    } else {
        (Some("unsupported"), Err(registry::Error::Unsupported))
    }
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
        registry::Error::Denied(_) => (StatusCode::FORBIDDEN, "DENIED"),
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
        registry::Error::Unauthorized(_) => Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .header(
                WWW_AUTHENTICATE,
                r#"Basic realm="Simple Registry", charset="UTF-8""#,
            )
            .body(Body::Fixed(Full::new(body)))
            .unwrap(),
        _ => Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::Fixed(Full::new(body)))
            .unwrap(),
    }
}
