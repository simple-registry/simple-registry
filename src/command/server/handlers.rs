//! The endpoints the registry does not serve: token exchange, the embedded web
//! UI, and the operational probes. Everything OCI answers from `registry`.

use std::borrow::Cow;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    HeaderMap, Response, StatusCode,
    header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue},
};
use rust_embed::Embed;
use serde::Serialize;

use crate::{
    auth::TokenIssuer,
    command::server::error::Error,
    http_response::{ResponseBody, build_response, json_headers, json_response},
    identity::ClientIdentity,
    metrics_provider::metrics_provider,
    registry::Registry,
};

/// The response field names are the ones OCI clients read.
#[derive(Serialize)]
pub struct TokenBody {
    token: String,
    expires_in: u64,
}

#[derive(Serialize)]
pub struct UiConfigBody {
    name: String,
}

#[derive(Serialize)]
pub struct StatusBody {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Embed)]
#[folder = "ui/build"]
struct UiAssets;

/// Exchanges the credential that authenticated this request for a
/// registry-issued token.
///
/// A registry token is not such a credential: renewing one would let a token
/// outlive the credential it was minted from forever, and `ttl_secs` would
/// bound nothing.
pub fn handle_get_token(
    token_issuer: &TokenIssuer,
    identity: &ClientIdentity,
) -> Result<Response<ResponseBody>, Error> {
    if identity.from_registry_token {
        return Err(Error::Unauthorized(
            "A registry token cannot be exchanged for another".to_string(),
        ));
    }

    let (token, expires_in) = token_issuer.issue(identity)?;
    let body = TokenBody { token, expires_in };
    // The body is a bearer credential, so no shared cache may store it and hand
    // it to the next client asking for one.
    let mut headers = json_headers();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    Ok(build_response(
        StatusCode::OK,
        headers,
        ResponseBody::fixed(serde_json::to_vec(&body)?),
    )?)
}

pub fn handle_ui_config(ui_name: &str) -> Result<Response<ResponseBody>, Error> {
    let body = UiConfigBody {
        name: ui_name.to_string(),
    };

    json_response(StatusCode::OK, &body)
}

pub fn handle_ui_asset(path: &str) -> Result<Response<ResponseBody>, Error> {
    let asset_path = path.trim_start_matches('/');
    let asset_path = if asset_path.is_empty() {
        "index.html"
    } else {
        asset_path
    };

    if let Some(content) = UiAssets::get(asset_path) {
        let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
        return asset_response(mime.as_ref(), content.data);
    }

    if let Some(content) = UiAssets::get("index.html") {
        return asset_response("text/html; charset=utf-8", content.data);
    }

    Err(Error::NotFound("UI asset not found".to_string()))
}

fn asset_response(mime: &str, data: Cow<'static, [u8]>) -> Result<Response<ResponseBody>, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::try_from(mime)?);

    Ok(build_response(
        StatusCode::OK,
        headers,
        ResponseBody::Fixed(Full::new(asset_bytes(data))),
    )?)
}

/// Wrap an embedded asset's bytes without copying them. A release build embeds
/// the assets, so the `Cow` borrows `'static` data every request shares; a debug
/// build reads each one from disk, and the `Bytes` takes that buffer over.
fn asset_bytes(data: Cow<'static, [u8]>) -> Bytes {
    match data {
        Cow::Borrowed(embedded) => Bytes::from_static(embedded),
        Cow::Owned(read_from_disk) => Bytes::from(read_from_disk),
    }
}

pub fn handle_healthz() -> Result<Response<ResponseBody>, Error> {
    let body = StatusBody {
        status: "ok",
        error: None,
    };

    json_response(StatusCode::OK, &body)
}

/// A backend that cannot be listed is reported as `503 not_ready` rather than
/// as an error, so the probe body carries the reason.
pub async fn handle_readyz(registry: &Registry) -> Result<Response<ResponseBody>, Error> {
    let (status, body) = match registry.check_ready().await {
        Ok(()) => (
            StatusCode::OK,
            StatusBody {
                status: "ready",
                error: None,
            },
        ),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            StatusBody {
                status: "not_ready",
                error: Some(error.to_string()),
            },
        ),
    };

    json_response(status, &body)
}

pub fn handle_metrics() -> Result<Response<ResponseBody>, Error> {
    let (content_type, metrics) = metrics_provider().gather()?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::try_from(content_type)?);

    Ok(build_response(
        StatusCode::OK,
        headers,
        ResponseBody::fixed(metrics),
    )?)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use bytes::Bytes;

    use super::asset_bytes;

    /// The embedded (release) shape: every request must share the one `'static`
    /// copy rather than allocating its own, which pointer identity is the only
    /// direct evidence of.
    #[test]
    fn borrowed_asset_is_served_without_copying() {
        static EMBEDDED: &[u8] = b"<!doctype html>";

        let served = asset_bytes(Cow::Borrowed(EMBEDDED));

        assert_eq!(served, EMBEDDED);
        assert_eq!(
            served.as_ptr(),
            EMBEDDED.as_ptr(),
            "an embedded asset must be served from its own storage, not a copy"
        );
    }

    /// The read-from-disk (debug) shape: the buffer is moved into the `Bytes`.
    #[test]
    fn owned_asset_keeps_its_buffer() {
        let read_from_disk = b"<!doctype html>".to_vec();
        let address = read_from_disk.as_ptr();

        let served = asset_bytes(Cow::Owned(read_from_disk));

        assert_eq!(served, Bytes::from_static(b"<!doctype html>"));
        assert_eq!(
            served.as_ptr(),
            address,
            "an asset read from disk must be handed over, not copied"
        );
    }
}
