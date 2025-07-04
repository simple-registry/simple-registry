use crate::registry::utils::sha256_ext::Sha256Ext;
use sha2::{Digest, Sha256};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashingReader<R> {
    pub fn with_hasher(inner: R, hasher: Sha256) -> Self {
        Self { inner, hasher }
    }

    pub fn serialized_state(&self) -> Vec<u8> {
        self.hasher.serialized_state()
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for HashingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pre_len = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let post_len = buf.filled().len();
            let new_data = &buf.filled()[pre_len..post_len];
            self.hasher.update(new_data);
        }
        poll
    }
}
