use crate::oci::{Descriptor, Digest};
use crate::registry::{Error, Registry};
use tracing::instrument;

impl Registry {
    #[instrument]
    pub async fn get_referrers(
        &self,
        namespace: &str,
        digest: Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, Error> {
        self.validate_namespace(namespace)?;

        match self
            .storage_engine
            .list_referrers(namespace, &digest, artifact_type)
            .await
        {
            Ok(referrers) => Ok(referrers),
            Err(Error::BlobUnknown) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    #[instrument]
    pub async fn list_catalog(
        &self,
        n: Option<u16>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let n = n.unwrap_or(100);

        let (namespaces, next_last) = self
            .storage_engine
            .list_revisions("test/nginx", n, last)
            .await?;
        let link = next_last.map(|next_last| format!("/v2/_catalog?n={n}&last={next_last}"));

        let namespaces = namespaces
            .into_iter()
            .map(|digest| digest.to_string())
            .collect();
        Ok((namespaces, link))
    }

    #[instrument]
    pub async fn list_tags(
        &self,
        namespace: &str,
        n: Option<u16>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        self.validate_namespace(namespace)?;

        let n = n.unwrap_or(100);

        let (tags, next_last) = self.storage_engine.list_tags(namespace, n, last).await?;
        let link =
            next_last.map(|next_last| format!("/v2/{namespace}/tags/list?n={n}&last={next_last}"));

        Ok((tags, link))
    }
}
