use std::borrow::Cow;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode, header::CONTENT_TYPE};
use rust_embed::Embed;

use crate::command::server::{error::Error, response_body::ResponseBody};

#[derive(Embed)]
#[folder = "ui/build"]
struct UiAssets;

pub fn serve_asset(path: &str) -> Result<Response<ResponseBody>, Error> {
    let asset_path = path.trim_start_matches('/');
    let asset_path = if asset_path.is_empty() {
        "index.html"
    } else {
        asset_path
    };

    if let Some(content) = UiAssets::get(asset_path) {
        let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
        return serve_bytes(mime.as_ref(), asset_bytes(content.data));
    }

    if let Some(content) = UiAssets::get("index.html") {
        return serve_bytes("text/html; charset=utf-8", asset_bytes(content.data));
    }

    Err(Error::NotFound("UI asset not found".to_string()))
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

fn serve_bytes(mime: &str, data: Bytes) -> Result<Response<ResponseBody>, Error> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, mime)
        .body(ResponseBody::Fixed(Full::new(data)))?)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        assert_eq!(served, b"<!doctype html>".as_slice());
        assert_eq!(
            served.as_ptr(),
            address,
            "an asset read from disk must be handed over, not copied"
        );
    }
}
