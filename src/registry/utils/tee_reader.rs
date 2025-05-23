use futures_util::future::try_join;
use hyper::body::Bytes;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::mpsc,
    task,
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;
use tracing::error;

/// A helper type that converts an MPSC Receiver of byte chunks into an `AsyncRead`.
pub struct ChannelReader {
    inner: StreamReader<ReceiverStream<io::Result<Bytes>>, Bytes>,
}

impl ChannelReader {
    pub fn new(rx: mpsc::Receiver<io::Result<Bytes>>) -> Self {
        // Wrap the receiver into a stream that yields Ok(Bytes) items.
        let stream = ReceiverStream::new(rx);
        Self {
            inner: StreamReader::new(stream),
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Tee the given `AsyncRead` into two `AsyncRead` handles.
///
/// This spawns a background task that continuously reads from the source
/// and sends copies of each chunk to two separate channels. Backpressure is handled
/// via bounded MPSC channels.
///
/// When the underlying reader returns EOF or an error, the channels are closed,
/// ending both streams.
///
/// # Arguments
/// - `reader`: The underlying source which implements `AsyncRead`.
/// - `buffer_size`: The size of the temporary read buffer.
///
/// # Returns
/// A future resolving to a pair of `AsyncRead` handles.
pub async fn tee_reader<R>(mut reader: R) -> io::Result<(ChannelReader, ChannelReader)>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (tx1, rx1) = mpsc::channel::<io::Result<Bytes>>(10);
    let (tx2, rx2) = mpsc::channel::<io::Result<Bytes>>(10);

    // Spawn a background task to read from the source.
    task::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break, // EOF reached.
                Ok(n) => {
                    let chunk = Bytes::copy_from_slice(&buf[..n]);
                    let send1 = tx1.send(Ok(chunk.clone()));
                    let send2 = tx2.send(Ok(chunk));
                    if try_join(send1, send2).await.is_err() {
                        // If at least one receiver has dropped, stop reading, and notify an error to the other.
                        tx1.send(Err(io::ErrorKind::BrokenPipe.into())).await.ok();
                        tx2.send(Err(io::ErrorKind::BrokenPipe.into())).await.ok();
                        break;
                    }
                }
                Err(error) => {
                    error!("Error reading from source: {error}");
                    let _ = try_join(
                        tx1.send(Err(error.kind().into())),
                        tx2.send(Err(error.kind().into())),
                    )
                    .await;
                    break;
                }
            }
        }
        // Dropping the senders signals EOF to the receivers.
    });

    let reader1 = ChannelReader::new(rx1);
    let reader2 = ChannelReader::new(rx2);

    Ok((reader1, reader2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tee_reader() {
        let data = b"hello world";
        let (mut reader1, mut reader2) = tee_reader(&data[..]).await.unwrap();

        let (result1, result2) = tokio::join!(
            async {
                let mut buf = Vec::new();
                reader1.read_to_end(&mut buf).await.unwrap();
                buf
            },
            async {
                let mut buf = Vec::new();
                reader2.read_to_end(&mut buf).await.unwrap();
                buf
            }
        );

        assert_eq!(result1, data);
        assert_eq!(result2, data);
    }
}
