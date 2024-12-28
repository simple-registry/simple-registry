use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body_util::{Full, StreamBody};
use hyper::body::{Body, Frame};
use hyper::{Response, StatusCode};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

use crate::error::RegistryError;

type BytesFrameStream = Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, io::Error>> + Send>>;

pub enum RegistryResponseBody {
    Empty,
    Fixed(Full<Bytes>),
    Streaming(StreamBody<BytesFrameStream>),
}

impl RegistryResponseBody {
    pub fn empty() -> Self {
        RegistryResponseBody::Empty
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
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            RegistryResponseBody::Empty => Poll::Ready(None),
            RegistryResponseBody::Fixed(body) => Pin::new(body)
                .poll_frame(cx)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            RegistryResponseBody::Streaming(body) => Pin::new(body).poll_frame(cx),
        }
    }
}

pub fn paginated_response(
    body: String,
    link: Option<String>,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let res = match link {
        Some(link) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("Link", format!("<{}>; rel=\"next\"", link))
            .body(RegistryResponseBody::fixed(body.into_bytes()))?,
        None => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(RegistryResponseBody::fixed(body.into_bytes()))?,
    };

    Ok(res)
}
