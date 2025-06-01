use futures_util::{Stream, StreamExt};
use http_body_util::{Full, StreamBody};
use hyper::body::{Bytes, Frame};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

type BytesFrameStream = Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, io::Error>> + Send>>;

pub enum Body {
    Empty,
    Fixed(Full<Bytes>),
    Streaming(StreamBody<BytesFrameStream>),
}

impl Body {
    pub fn empty() -> Self {
        Body::Empty
    }

    pub fn fixed(data: Vec<u8>) -> Self {
        let data = Bytes::from(data);
        Body::Fixed(Full::new(data))
    }

    pub fn streaming<R>(reader: R) -> Self
    where
        R: AsyncRead + Send + 'static,
    {
        let stream = ReaderStream::new(reader).map(|result| result.map(Frame::data));
        Body::Streaming(StreamBody::new(Box::pin(stream)))
    }
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Body::Empty => Poll::Ready(None),
            Body::Fixed(body) => Pin::new(body).poll_frame(cx).map_err(io::Error::other),
            Body::Streaming(body) => Pin::new(body).poll_frame(cx),
        }
    }
}
