use crate::error::RegistryError;
use crate::oci::{Descriptor, Digest};
use crate::registry::Registry;

impl Registry {
    pub async fn get_referrers(
        &self,
        namespace: &str,
        digest: Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, RegistryError> {
        self.validate_namespace(namespace)?;

        let referrers = self
            .storage
            .list_referrers(namespace, &digest, artifact_type)
            .await
            .unwrap_or_default();

        Ok(referrers)
    }

    pub async fn list_catalog(
        &self,
        n: Option<u32>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        let (n, last) = (n.unwrap_or(100), last.unwrap_or_default());

        let (namespaces, next_last) = self.storage.read_catalog(n, last).await?;
        let link = next_last.map(|next_last| format!("/v2/_catalog?n={}&last={}", n, next_last));

        Ok((namespaces, link))
    }

    pub async fn list_tags(
        &self,
        namespace: &str,
        n: Option<u32>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        self.validate_namespace(namespace)?;

        let (n, last) = (n.unwrap_or(100), last.unwrap_or_default());

        let (tags, next_last) = self.storage.list_tags(namespace, n, last).await?;
        let link = next_last
            .map(|next_last| format!("/v2/{}/tags/list?n={}&last={}", namespace, n, next_last));

        Ok((tags, link))
    }
}
