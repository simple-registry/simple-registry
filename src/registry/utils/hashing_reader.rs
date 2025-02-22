use crate::registry::data_store::Error;
use crate::registry::utils::sha256_ext::Sha256Ext;
use sha2::{Digest as Sha256Digest, Sha256};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

/// A wrapper around an `AsyncRead` that computes a SHA256 hash on the fly.
pub struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashingReader<R> {
    pub fn with_hash_state(inner: R, hash_state: &[u8]) -> Result<Self, Error> {
        let hasher = Sha256::deserialize_state(hash_state)?;
        Ok(Self { inner, hasher })
    }

    /// Returns the current SHA256 hash state.
    ///
    /// Note that if the stream has not been fully read, the returned hash state
    /// reflects the bytes that have been seen so far.
    pub fn hash_state(&self) -> Vec<u8> {
        self.hasher.serialize_state()
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for HashingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pre_len = buf.filled().len();

        let inner = Pin::new(&mut self.inner);
        match inner.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let post_len = buf.filled().len();
                if post_len > pre_len {
                    let new_data = &buf.filled()[pre_len..post_len];
                    self.hasher.update(new_data);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_hashing_reader() {
        let data = b"hello world";
        let mut reader = HashingReader {
            inner: io::Cursor::new(data),
            hasher: Sha256::new(),
        };

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        let mut expected_hasher = Sha256::new();
        expected_hasher.update(data);
        let expected_hasher_state = expected_hasher.serialize_state();

        let actual_state = reader.hash_state();

        assert_eq!(expected_hasher_state, actual_state);
    }
}
