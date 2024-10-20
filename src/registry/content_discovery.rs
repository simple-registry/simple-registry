use crate::error::RegistryError;
use crate::oci::{Descriptor, Digest};
use crate::registry::Registry;
use tracing::instrument;

impl Registry {
    #[instrument]
    pub async fn get_referrers(
        &self,
        namespace: &str,
        digest: Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, RegistryError> {
        self.validate_namespace(namespace)?;

        let _guard = self
            .read_lock(&digest)
            .await?;

        match self
            .storage
            .list_referrers(namespace, &digest, artifact_type)
            .await
        {
            Ok(referrers) => Ok(referrers.collect()),
            Err(RegistryError::BlobUnknown) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    #[instrument]
    pub async fn list_catalog(
        &self,
        n: Option<u32>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        let n = n.unwrap_or(100);

        let mut namespaces = self.storage.list_namespaces().await?;

        if let Some(last) = last {
            for namespace in namespaces.by_ref() {
                if namespace == last {
                    break;
                }
            }
        }

        let namespaces = namespaces.take(n as usize).collect::<Vec<_>>();
        let next_last = namespaces.last().cloned();

        let link = next_last.map(|next_last| format!("/v2/_catalog?n={}&last={}", n, next_last));

        Ok((namespaces, link))
    }

    #[instrument]
    pub async fn list_tags(
        &self,
        namespace: &str,
        n: Option<u32>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        self.validate_namespace(namespace)?;

        let n = n.unwrap_or(100);

        let mut tags = self.storage.list_tags(namespace).await?;

        if let Some(last) = last {
            for tag in tags.by_ref() {
                if tag == last {
                    break;
                }
            }
        }

        let tags = tags.take(n as usize).collect::<Vec<_>>();
        let next_last = tags.last().cloned();

        let link = next_last
            .map(|next_last| format!("/v2/{}/tags/list?n={}&last={}", namespace, n, next_last));

        Ok((tags, link))
    }
}
