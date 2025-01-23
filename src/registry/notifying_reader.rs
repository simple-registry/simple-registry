use crate::storage::Reader;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::error;

pub struct NotifyingReader<R: Reader> {
    inner: R,
    sender: Sender<Vec<u8>>,
}

impl<R: Reader> NotifyingReader<R> {
    pub fn new(inner: R, buffer_size: usize) -> (Self, Receiver<Vec<u8>>) {
        let (sender, receiver) = mpsc::channel::<Vec<u8>>(buffer_size);
        let reader = NotifyingReader { inner, sender };

        (reader, receiver)
    }
}

impl<R: Reader> AsyncRead for NotifyingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let post_len = buf.filled().len();
                let start = 0;
                let end = post_len;

                let chunk = buf.filled()[start..end].to_vec();

                if chunk.is_empty() {
                    return Poll::Ready(Ok(()));
                }

                // TODO: We should re-try sending the chunk if the receiver is full
                if let Err(e) = self.sender.try_send(chunk) {
                    error!("Failed to send chunk: {}", e);
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                error!("Failed to read from inner reader: {}", e);
                Poll::Ready(Err(e))
            }
            other => other,
        }
    }
}
