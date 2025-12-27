use std::sync::Arc;

use chrono::Duration;
use tracing::info;

use crate::registry::blob_store::{Error, MultipartCleanup};

pub struct MultipartChecker {
    cleanup: Arc<dyn MultipartCleanup + Send + Sync>,
    timeout: Duration,
    dry_run: bool,
}

impl MultipartChecker {
    pub fn new(
        cleanup: Arc<dyn MultipartCleanup + Send + Sync>,
        timeout: Duration,
        dry_run: bool,
    ) -> Self {
        Self {
            cleanup,
            timeout,
            dry_run,
        }
    }

    pub async fn check_all(&self) -> Result<(), Error> {
        let count = self
            .cleanup
            .cleanup_orphan_multipart_uploads(self.timeout, self.dry_run)
            .await?;
        info!("Cleaned up {count} orphan multipart upload(s)");
        Ok(())
    }
}
