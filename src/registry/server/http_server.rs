use crate::metrics_provider::{IN_FLIGHT_REQUESTS, METRICS_PROVIDER};
use crate::registry::server::auth::PeerCertificate;
use crate::registry::server::request_ext::{HeaderExt, IntoAsyncRead};
use crate::registry::server::route::Route;
use crate::registry::server::{router, ServerContext};
use crate::registry::{Error, ResponseBody};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_RANGE, CONTENT_TYPE, RANGE, WWW_AUTHENTICATE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use opentelemetry::trace::TraceContextExt;
use serde::Serialize;
use serde_json::json;
use std::convert::Infallible;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::pin;
use tracing::{debug, error, info, instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub async fn serve_request<S>(
    stream: TokioIo<S>,
    context: Arc<ServerContext>,
    peer_certificate: Option<Vec<u8>>,
    timeouts: Arc<[Duration; 2]>,
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
        Err(error) => {
            let details = trace_id
                .as_ref()
                .map(|trace_id| json!({"trace_id": trace_id}))
                .unwrap_or(json!({}));
            registry_error_to_response_raw(&error, details)
        }
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
    let identity = context.authenticate_request(&parts).await?;
    context.registry.validate_request(&route, &identity).await?;

    match route {
        Route::Unknown => {
            if [Method::GET, Method::HEAD].contains(&parts.method) {
                Err(Error::NotFound)
            } else {
                Err(Error::Unsupported)
            }
        }
        Route::ApiVersion => context.registry.handle_get_api_version().await,
        Route::StartUpload { namespace, digest } => {
            context
                .registry
                .handle_start_upload(namespace, digest)
                .await
        }
        Route::GetUpload { namespace, uuid } => {
            context.registry.handle_get_upload(namespace, uuid).await
        }
        Route::PatchUpload { namespace, uuid } => {
            let start_offset = parts.range(CONTENT_RANGE)?.map(|(start, _)| start);
            let body_stream = incoming.into_async_read();

            context
                .registry
                .handle_patch_upload(namespace, uuid, start_offset, body_stream)
                .await
        }
        Route::PutUpload {
            namespace,
            uuid,
            digest,
        } => {
            let body_stream = incoming.into_async_read();

            context
                .registry
                .handle_put_upload(namespace, uuid, &digest, body_stream)
                .await
        }
        Route::DeleteUpload { namespace, uuid } => {
            context.registry.handle_delete_upload(namespace, uuid).await
        }
        Route::GetBlob { namespace, digest } => {
            let mime_types = parts.accepted_content_types();
            let range = parts.range(RANGE)?;

            context
                .registry
                .handle_get_blob(namespace, &digest, &mime_types, range)
                .await
        }
        Route::HeadBlob { namespace, digest } => {
            let mime_types = parts.accepted_content_types();

            context
                .registry
                .handle_head_blob(namespace, &digest, &mime_types)
                .await
        }
        Route::DeleteBlob { namespace, digest } => {
            context
                .registry
                .handle_delete_blob(namespace, &digest)
                .await
        }
        Route::GetManifest {
            namespace,
            reference,
        } => {
            let mime_types = parts.accepted_content_types();

            context
                .registry
                .handle_get_manifest(namespace, reference, &mime_types)
                .await
        }
        Route::HeadManifest {
            namespace,
            reference,
        } => {
            let mime_types = parts.accepted_content_types();

            context
                .registry
                .handle_head_manifest(namespace, reference, &mime_types)
                .await
        }
        Route::PutManifest {
            namespace,
            reference,
        } => {
            let mime_type = parts
                .get_header(CONTENT_TYPE)
                .ok_or(Error::ManifestInvalid(
                    "No Content-Type header provided".to_string(),
                ))?;

            let body_stream = incoming.into_async_read();

            context
                .registry
                .handle_put_manifest(namespace, reference, mime_type, body_stream)
                .await
        }
        Route::DeleteManifest {
            namespace,
            reference,
        } => {
            context
                .registry
                .handle_delete_manifest(namespace, reference)
                .await
        }
        Route::GetReferrer {
            namespace,
            digest,
            artifact_type,
        } => {
            context
                .registry
                .handle_get_referrers(namespace, &digest, artifact_type)
                .await
        }
        Route::ListCatalog { n, last } => context.registry.handle_list_catalog(n, last).await,
        Route::ListTags { namespace, n, last } => {
            context.registry.handle_list_tags(namespace, n, last).await
        }
        Route::Healthz => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(ResponseBody::Fixed(Full::new(Bytes::from(
                r#"{"status":"ok"}"#,
            ))))?),
        Route::Metrics => {
            let (content_type, metrics) = METRICS_PROVIDER.gather()?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, content_type)
                .body(ResponseBody::Fixed(Full::new(Bytes::from(metrics))))?)
        }
    }
}

pub fn registry_error_to_response_raw<T>(error: &Error, details: T) -> Response<ResponseBody>
where
    T: Serialize,
{
    let (status, code) = match error {
        Error::BlobUnknown => (StatusCode::NOT_FOUND, "BLOB_UNKNOWN"),
        //RegistryError::BlobUploadInvalid => (StatusCode::BAD_REQUEST, "BLOB_UPLOAD_INVALID"),
        Error::BlobUploadUnknown => (StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN"),
        Error::DigestInvalid => (StatusCode::BAD_REQUEST, "DIGEST_INVALID"),
        Error::ManifestBlobUnknown => (StatusCode::NOT_FOUND, "MANIFEST_BLOB_UNKNOWN"),
        Error::ManifestInvalid(_) => (StatusCode::BAD_REQUEST, "MANIFEST_INVALID"),
        Error::ManifestUnknown => (StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN"),
        Error::NameInvalid => (StatusCode::BAD_REQUEST, "NAME_INVALID"),
        Error::NameUnknown => (StatusCode::NOT_FOUND, "NAME_UNKNOWN"),
        //RegistryError::SizeInvalid => (StatusCode::BAD_REQUEST, "SIZE_INVALID"),
        Error::TagImmutable(_) => (StatusCode::CONFLICT, "TAG_IMMUTABLE"),
        Error::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
        Error::Denied(_) => (StatusCode::FORBIDDEN, "DENIED"),
        Error::Unsupported => (StatusCode::BAD_REQUEST, "UNSUPPORTED"),
        //RegistryError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "TOOMANYREQUESTS"),
        // Convenience
        Error::RangeNotSatisfiable => (StatusCode::RANGE_NOT_SATISFIABLE, "SIZE_INVALID"), // Can't find a better code from the OCI spec
        // Catch-all
        Error::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR"),
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
