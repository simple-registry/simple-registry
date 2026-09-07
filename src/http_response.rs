//! Response construction shared by the registry, which builds the responses to
//! its own operations, and the server surface, which builds the ones that never
//! reach the registry (errors, tokens, UI assets, probes).

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use angos_oci::header::APPLICATION_JSON;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http::{HeaderMap, Response, StatusCode, header::CONTENT_TYPE};
use http_body_util::{Full, StreamBody};
use hyper::body::{Body, Frame};
use serde::Serialize;
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

type BytesFrameStream = Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, io::Error>> + Send>>;

/// The headers of a plain JSON response, the shape most non-OCI endpoints
/// serve.
pub fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, APPLICATION_JSON);

    headers
}

/// A JSON response under [`json_headers`]. Generic over the caller's error so
/// the registry and the server surface share one builder.
pub fn json_response<T, E>(status: StatusCode, body: &T) -> Result<Response<ResponseBody>, E>
where
    T: Serialize,
    E: From<http::Error> + From<serde_json::Error>,
{
    Ok(build_response(
        status,
        json_headers(),
        ResponseBody::fixed(serde_json::to_vec(body)?),
    )?)
}

pub enum ResponseBody {
    Empty,
    Fixed(Full<Bytes>),
    Streaming(StreamBody<BytesFrameStream>),
}

impl ResponseBody {
    pub fn empty() -> Self {
        ResponseBody::Empty
    }

    pub fn fixed(data: Vec<u8>) -> Self {
        let data = Bytes::from(data);
        ResponseBody::Fixed(Full::new(data))
    }

    pub fn streaming<R>(reader: R) -> Self
    where
        R: AsyncRead + Send + 'static,
    {
        let stream = ReaderStream::new(reader).map(|result| result.map(Frame::data));
        ResponseBody::Streaming(StreamBody::new(Box::pin(stream)))
    }
}

impl fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ResponseBody::Empty => "Empty",
            ResponseBody::Fixed(_) => "Fixed",
            ResponseBody::Streaming(_) => "Streaming",
        })
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ResponseBody::Empty => Poll::Ready(None),
            ResponseBody::Fixed(body) => Pin::new(body).poll_frame(cx).map_err(io::Error::other),
            ResponseBody::Streaming(body) => Pin::new(body).poll_frame(cx),
        }
    }
}

pub fn build_response(
    status: StatusCode,
    headers: HeaderMap,
    body: ResponseBody,
) -> Result<Response<ResponseBody>, http::Error> {
    let mut response = Response::builder().status(status).body(body)?;
    *response.headers_mut() = headers;

    Ok(response)
}
