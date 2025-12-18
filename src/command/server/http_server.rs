use std::convert::Infallible;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_RANGE, CONTENT_TYPE, RANGE, WWW_AUTHENTICATE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use opentelemetry::trace::TraceContextExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::pin;
use tracing::{Span, debug, error, info, instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::command::server::auth::PeerCertificate;
use crate::command::server::error::Error;
use crate::command::server::request_ext::{HeaderExt, IntoAsyncRead};
use crate::command::server::response_body::ResponseBody;
use crate::command::server::route::Route;
use crate::command::server::{ServerContext, router};
use crate::metrics_provider::{IN_FLIGHT_REQUESTS, METRICS_PROVIDER};
use crate::oci::Reference;

pub async fn serve_request<S>(
    stream: TokioIo<S>,
    context: Arc<ServerContext>,
    peer_certificate: Option<Vec<u8>>,
    timeouts: Arc<[Duration; 2]>,
    remote_address: std::net::SocketAddr,
) where
    S: Unpin + AsyncWrite + AsyncRead + Send + Debug + 'static,
{
    let conn = http1::Builder::new().serve_connection(
        stream,
        service_fn(move |mut request| {
            if let Some(ref cert_data) = peer_certificate {
                let peer_certificate = PeerCertificate(Arc::new(cert_data.clone()));
                request.extensions_mut().insert(peer_certificate);
            }
            request.extensions_mut().insert(remote_address);
            handle_request(Arc::clone(&context), request)
        }),
    );
    pin!(conn);

    IN_FLIGHT_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    METRICS_PROVIDER.metric_http_request_in_flight.set(
        i64::try_from(IN_FLIGHT_REQUESTS.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(i64::MAX),
    );

    for (iter, sleep_duration) in timeouts.iter().enumerate() {
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
    METRICS_PROVIDER.metric_http_request_in_flight.set(
        i64::try_from(IN_FLIGHT_REQUESTS.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(i64::MAX),
    );
}

#[instrument(skip(context, request))]
async fn handle_request(
    context: Arc<ServerContext>,
    request: Request<Incoming>,
) -> Result<Response<ResponseBody>, Infallible> {
    let start_time = Instant::now();
    let method = request.method().to_owned();
    let path = request.uri().path().to_owned();

    let trace_id = {
        let context = Span::current().context();
        let span = context.span();
        let span_context = span.span_context();
        if span_context.is_valid() {
            Some(span_context.trace_id().to_string())
        } else {
            None
        }
    };

    let response = match router(Arc::clone(&context), request).await {
        Ok(response) => response,
        Err(error) => error_to_response(&error, trace_id.as_ref()),
    };

    #[allow(clippy::cast_precision_loss)]
    let elapsed = start_time.elapsed().as_millis() as f64;
    let status = response.status();

    METRICS_PROVIDER.metric_http_request_total.inc();
    METRICS_PROVIDER
        .metric_http_request_duration
        .observe(elapsed);

    let log = if let Some(trace_id) = trace_id {
        format!("{trace_id} {elapsed:?} - {status} {method} {path}")
    } else {
        format!("{elapsed:?} - {status} {method} {path}")
    };

    if status.is_server_error() {
        error!("{log}");
    } else {
        info!("{log}");
    }

    Ok(response)
}

#[allow(clippy::too_many_lines)]
#[instrument(skip(context, req))]
async fn router(
    context: Arc<ServerContext>,
    req: Request<Incoming>,
) -> Result<Response<ResponseBody>, Error> {
    let (parts, incoming) = req.into_parts();

    let route = router::parse(&parts.method, &parts.uri);
    let remote_address = parts.extensions.get::<std::net::SocketAddr>().copied();
    let identity = context.authenticate_request(&parts, remote_address).await?;
    context.authorize_request(&route, &identity, &parts).await?;

    match route {
        Route::Unknown => {
            if [Method::GET, Method::HEAD].contains(&parts.method) {
                let msg = format!("unknown route: {} {}", parts.method, parts.uri);
                Err(Error::NotFound(msg))
            } else {
                let msg = format!("unsupported route: {} {}", parts.method, parts.uri);
                Err(Error::BadRequest(msg))
            }
        }
        Route::ApiVersion => Ok(context.registry.handle_get_api_version().await?),
        Route::StartUpload { namespace, digest } => Ok(context
            .registry
            .handle_start_upload(namespace, digest)
            .await?),
        Route::GetUpload { namespace, uuid } => {
            Ok(context.registry.handle_get_upload(namespace, uuid).await?)
        }
        Route::PatchUpload { namespace, uuid } => {
            let start_offset = parts.range(CONTENT_RANGE)?.map(|(start, _)| start);
            let body_stream = incoming.into_async_read();

            Ok(context
                .registry
                .handle_patch_upload(namespace, uuid, start_offset, body_stream)
                .await?)
        }
        Route::PutUpload {
            namespace,
            uuid,
            digest,
        } => {
            let body_stream = incoming.into_async_read();

            Ok(context
                .registry
                .handle_put_upload(namespace, uuid, &digest, body_stream)
                .await?)
        }
        Route::DeleteUpload { namespace, uuid } => Ok(context
            .registry
            .handle_delete_upload(namespace, uuid)
            .await?),
        Route::GetBlob { namespace, digest } => {
            let mime_types = parts.accepted_content_types();
            let range = parts.range(RANGE)?;

            Ok(context
                .registry
                .handle_get_blob(namespace, &digest, &mime_types, range)
                .await?)
        }
        Route::HeadBlob { namespace, digest } => {
            let mime_types = parts.accepted_content_types();

            Ok(context
                .registry
                .handle_head_blob(namespace, &digest, &mime_types)
                .await?)
        }
        Route::DeleteBlob { namespace, digest } => Ok(context
            .registry
            .handle_delete_blob(namespace, &digest)
            .await?),
        Route::GetManifest {
            namespace,
            reference,
        } => {
            let mime_types = parts.accepted_content_types();
            let is_tag_immutable = match &reference {
                Reference::Tag(tag) => context.is_tag_immutable(namespace, tag.as_str()),
                Reference::Digest(_) => false,
            };

            Ok(context
                .registry
                .handle_get_manifest(namespace, reference, &mime_types, is_tag_immutable)
                .await?)
        }
        Route::HeadManifest {
            namespace,
            reference,
        } => {
            let mime_types = parts.accepted_content_types();
            let is_tag_immutable = match &reference {
                Reference::Tag(tag) => context.is_tag_immutable(namespace, tag.as_str()),
                Reference::Digest(_) => false,
            };

            Ok(context
                .registry
                .handle_head_manifest(namespace, reference, &mime_types, is_tag_immutable)
                .await?)
        }
        Route::PutManifest {
            namespace,
            reference,
        } => {
            let mime_type = parts.get_header(CONTENT_TYPE).ok_or(Error::BadRequest(
                "No Content-Type header provided".to_string(),
            ))?;

            let body_stream = incoming.into_async_read();

            Ok(context
                .registry
                .handle_put_manifest(namespace, reference, mime_type, body_stream)
                .await?)
        }
        Route::DeleteManifest {
            namespace,
            reference,
        } => Ok(context
            .registry
            .handle_delete_manifest(namespace, reference)
            .await?),
        Route::GetReferrer {
            namespace,
            digest,
            artifact_type,
        } => Ok(context
            .registry
            .handle_get_referrers(namespace, &digest, artifact_type)
            .await?),
        Route::ListCatalog { n, last } => Ok(context.registry.handle_list_catalog(n, last).await?),
        Route::ListTags { namespace, n, last } => Ok(context
            .registry
            .handle_list_tags(namespace, n, last)
            .await?),
        Route::Healthz => handle_healthz(),
        Route::Metrics => handle_metrics(),
    }
}

fn handle_healthz() -> Result<Response<ResponseBody>, Error> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(ResponseBody::Fixed(Full::new(Bytes::from(
            r#"{"status":"ok"}"#,
        ))));

    match response {
        Ok(resp) => Ok(resp),
        Err(e) => {
            let msg = format!("Failed to build healthz response: {e}");
            Err(Error::Internal(msg))
        }
    }
}

fn handle_metrics() -> Result<Response<ResponseBody>, Error> {
    let (content_type, metrics) = METRICS_PROVIDER.gather()?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .body(ResponseBody::Fixed(Full::new(Bytes::from(metrics))));

    match response {
        Ok(resp) => Ok(resp),
        Err(e) => {
            let msg = format!("Failed to build metrics response: {e}");
            Err(Error::Internal(msg))
        }
    }
}

pub fn error_to_response(error: &Error, request_id: Option<&String>) -> Response<ResponseBody> {
    let status = error.status_code();
    let body = error.as_json(request_id);

    let body = body.to_string();
    let body = Bytes::from(body);

    match error {
        Error::Unauthorized(_) => Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .header(
                WWW_AUTHENTICATE,
                r#"Basic realm="Simple Registry", charset="UTF-8""#,
            )
            .body(ResponseBody::Fixed(Full::new(body)))
            .unwrap(),
        _ => Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(ResponseBody::Fixed(Full::new(body)))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry;

    #[test]
    fn test_error_to_response_unauthorized_with_request_id() {
        let error = Error::Unauthorized("Invalid credentials".to_string());
        let request_id = Some("req-123".to_string());

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE).unwrap(),
            r#"Basic realm="Simple Registry", charset="UTF-8""#
        );
    }

    #[test]
    fn test_error_to_response_unauthorized_without_request_id() {
        let error = Error::Unauthorized("Access denied".to_string());
        let request_id = None;

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE).unwrap(),
            r#"Basic realm="Simple Registry", charset="UTF-8""#
        );
    }

    #[test]
    fn test_error_to_response_not_found() {
        let error = Error::NotFound("Resource not found".to_string());
        let request_id = Some("req-456".to_string());

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }

    #[test]
    fn test_error_to_response_bad_request() {
        let error = Error::BadRequest("Invalid input".to_string());
        let request_id = None;

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }

    #[test]
    fn test_error_to_response_internal() {
        let error = Error::Internal("Server error".to_string());
        let request_id = Some("req-789".to_string());

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }

    #[test]
    fn test_error_to_response_from_registry_error() {
        let registry_error = registry::Error::BlobUnknown;
        let error: Error = registry_error.into();
        let request_id = Some("req-blob".to_string());

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_error_to_response_range_not_satisfiable() {
        let error = Error::RangeNotSatisfiable("Invalid range".to_string());
        let request_id = None;

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_error_to_response_conflict() {
        let error = Error::Conflict("Resource conflict".to_string());
        let request_id = Some("req-conflict".to_string());

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_error_to_response_initialization() {
        let error = Error::Initialization("Failed to start".to_string());
        let request_id = None;

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }

    #[test]
    fn test_error_to_response_custom_error() {
        let error = Error::Custom {
            status_code: StatusCode::BAD_GATEWAY,
            code: "UPSTREAM_ERROR".to_string(),
            msg: Some("Failed to connect".to_string()),
        };
        let request_id = Some("req-custom".to_string());

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }

    #[test]
    fn test_handle_healthz_success() {
        let result = handle_healthz();

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn test_handle_healthz_body_content() {
        use http_body_util::BodyExt;

        let result = handle_healthz();
        assert!(result.is_ok());

        let response = result.unwrap();
        let (_, body) = response.into_parts();

        let body_bytes = match body {
            ResponseBody::Fixed(b) => b.collect().await.unwrap().to_bytes(),
            _ => panic!("Expected Fixed body"),
        };

        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, r#"{"status":"ok"}"#);
    }

    #[test]
    fn test_handle_metrics_success() {
        let result = handle_metrics();

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(CONTENT_TYPE).is_some());
    }

    #[tokio::test]
    async fn test_handle_metrics_body_not_empty() {
        use http_body_util::BodyExt;

        let result = handle_metrics();
        assert!(result.is_ok());

        let response = result.unwrap();
        let (_, body) = response.into_parts();

        let body_bytes = match body {
            ResponseBody::Fixed(b) => b.collect().await.unwrap().to_bytes(),
            _ => panic!("Expected Fixed body"),
        };

        assert!(!body_bytes.is_empty());
    }

    #[tokio::test]
    async fn test_handle_metrics_contains_metric_data() {
        use http_body_util::BodyExt;

        let result = handle_metrics();
        assert!(result.is_ok());

        let response = result.unwrap();
        let (parts, body) = response.into_parts();

        let content_type = parts.headers.get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert!(content_type.contains("text/plain") || content_type.contains("application/json"));

        let body_bytes = match body {
            ResponseBody::Fixed(b) => b.collect().await.unwrap().to_bytes(),
            _ => panic!("Expected Fixed body"),
        };

        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(!body_str.is_empty());
    }

    #[test]
    fn test_error_to_response_all_error_types() {
        let errors = vec![
            (
                Error::Unauthorized("msg".to_string()),
                StatusCode::UNAUTHORIZED,
                true,
            ),
            (
                Error::NotFound("msg".to_string()),
                StatusCode::NOT_FOUND,
                false,
            ),
            (
                Error::BadRequest("msg".to_string()),
                StatusCode::BAD_REQUEST,
                false,
            ),
            (
                Error::Internal("msg".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
            ),
            (
                Error::Conflict("msg".to_string()),
                StatusCode::CONFLICT,
                false,
            ),
            (
                Error::RangeNotSatisfiable("msg".to_string()),
                StatusCode::RANGE_NOT_SATISFIABLE,
                false,
            ),
            (
                Error::Initialization("msg".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
            ),
            (
                Error::Execution("msg".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
            ),
        ];

        for (error, expected_status, should_have_www_authenticate) in errors {
            let response = error_to_response(&error, None);

            assert_eq!(response.status(), expected_status);
            assert_eq!(
                response.headers().get(CONTENT_TYPE).unwrap(),
                "application/json"
            );

            if should_have_www_authenticate {
                assert!(response.headers().get(WWW_AUTHENTICATE).is_some());
            } else {
                assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
            }
        }
    }

    #[test]
    fn test_error_to_response_preserves_request_id() {
        let error = Error::Internal("Test error".to_string());
        let request_id = Some("test-request-123".to_string());

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_error_to_response_body_contains_error_message() {
        use http_body_util::BodyExt;

        let error = Error::BadRequest("Invalid manifest format".to_string());
        let request_id = Some("req-manifest".to_string());

        let response = error_to_response(&error, request_id.as_ref());
        let (_, body) = response.into_parts();

        let body_bytes = match body {
            ResponseBody::Fixed(b) => b.collect().await.unwrap().to_bytes(),
            _ => panic!("Expected Fixed body"),
        };

        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("errors"));
    }

    #[test]
    fn test_error_to_response_unauthorized_realm() {
        let error = Error::Unauthorized("Invalid token".to_string());
        let request_id = None;

        let response = error_to_response(&error, request_id.as_ref());

        let www_authenticate = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();

        assert!(www_authenticate.contains("Basic"));
        assert!(www_authenticate.contains("realm"));
        assert!(www_authenticate.contains("Simple Registry"));
        assert!(www_authenticate.contains("UTF-8"));
    }

    #[test]
    fn test_error_to_response_with_empty_message() {
        let error = Error::Internal(String::new());
        let request_id = None;

        let response = error_to_response(&error, request_id.as_ref());

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_error_to_response_multiple_errors_same_request_id() {
        let request_id = Some("shared-req-id".to_string());

        let error1 = Error::NotFound("Resource 1".to_string());
        let response1 = error_to_response(&error1, request_id.as_ref());
        assert_eq!(response1.status(), StatusCode::NOT_FOUND);

        let error2 = Error::BadRequest("Bad input".to_string());
        let response2 = error_to_response(&error2, request_id.as_ref());
        assert_eq!(response2.status(), StatusCode::BAD_REQUEST);
    }
}
