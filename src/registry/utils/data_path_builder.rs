use crate::registry::oci_types::Digest;
use crate::registry::utils::BlobLink;

#[derive(Debug)]
pub struct DataPathBuilder {
    pub prefix: String,
}

impl DataPathBuilder {
    pub fn new(prefix: String) -> Self {
        Self { prefix }
    }

    pub fn blobs_root_dir(&self) -> String {
        if self.prefix.is_empty() {
            "v2/blobs".to_string()
        } else {
            format!("{}/v2/blobs", self.prefix)
        }
    }

    pub fn blob_container_dir(&self, digest: &Digest) -> String {
        format!(
            "{}/{}/{}/{}",
            self.blobs_root_dir(),
            digest.algorithm(),
            digest.hash_prefix(),
            digest.hash()
        )
    }

    pub fn blob_path(&self, digest: &Digest) -> String {
        format!("{}/data", self.blob_container_dir(digest))
    }

    pub fn blob_index_path(&self, digest: &Digest) -> String {
        format!("{}/index.json", self.blob_container_dir(digest))
    }

    pub fn repository_dir(&self) -> String {
        if self.prefix.is_empty() {
            "v2/repositories".to_string()
        } else {
            format!("{}/v2/repositories", self.prefix)
        }
    }

    pub fn uploads_root_dir(&self, namespace: &str) -> String {
        format!("{}/{namespace}/_uploads", self.repository_dir())
    }

    pub fn upload_container_path(&self, name: &str, uuid: &str) -> String {
        format!("{}/{uuid}", self.uploads_root_dir(name))
    }

    pub fn upload_path(&self, name: &str, uuid: &str) -> String {
        format!("{}/data", self.upload_container_path(name, uuid))
    }

    pub fn upload_staged_container_path(&self, name: &str, uuid: &str, offset: u64) -> String {
        format!("{}/{uuid}/staged/{offset}", self.uploads_root_dir(name))
    }

    pub fn upload_hash_context_container_path(
        &self,
        name: &str,
        uuid: &str,
        algorithm: &str,
    ) -> String {
        format!(
            "{}/{uuid}/hashstates/{algorithm}",
            self.uploads_root_dir(name),
        )
    }

    pub fn upload_hash_context_path(
        &self,
        name: &str,
        uuid: &str,
        algorithm: &str,
        offset: u64,
    ) -> String {
        format!(
            "{}/{offset}",
            self.upload_hash_context_container_path(name, uuid, algorithm)
        )
    }

    pub fn upload_start_date_container_dir(&self, name: &str, uuid: &str) -> String {
        format!("{}/{uuid}", self.uploads_root_dir(name))
    }

    pub fn upload_start_date_path(&self, name: &str, uuid: &str) -> String {
        format!(
            "{}/startedat",
            self.upload_start_date_container_dir(name, uuid),
        )
    }

    pub fn manifests_root_dir(&self, namespace: &str) -> String {
        format!("{}/{namespace}/_manifests", self.repository_dir())
    }

    pub fn manifest_revisions_link_root_dir(&self, name: &str, algorithm: &str) -> String {
        format!("{}/revisions/{algorithm}", self.manifests_root_dir(name))
    }

    pub fn manifest_revisions_link_container_dir(&self, name: &str, digest: &Digest) -> String {
        format!(
            "{}/{}",
            self.manifest_revisions_link_root_dir(name, digest.algorithm()),
            digest.hash()
        )
    }

    pub fn manifest_revisions_link_path(&self, name: &str, digest: &Digest) -> String {
        format!(
            "{}/link",
            self.manifest_revisions_link_container_dir(name, digest)
        )
    }

    pub fn layers_root_dir(&self, namespace: &str) -> String {
        format!("{}/{namespace}/_layers", self.repository_dir())
    }

    pub fn manifest_layer_link_container_dir(&self, name: &str, digest: &Digest) -> String {
        format!(
            "{}/{}/{}",
            self.layers_root_dir(name),
            digest.algorithm(),
            digest.hash()
        )
    }

    pub fn manifest_layer_link_path(&self, name: &str, digest: &Digest) -> String {
        format!(
            "{}/link",
            self.manifest_layer_link_container_dir(name, digest)
        )
    }

    pub fn config_root_dir(&self, namespace: &str) -> String {
        format!("{}/{namespace}/_config", self.repository_dir())
    }

    pub fn manifest_config_link_container_dir(&self, name: &str, digest: &Digest) -> String {
        format!(
            "{}/{}/{}",
            self.config_root_dir(name),
            digest.algorithm(),
            digest.hash()
        )
    }

    pub fn manifest_config_link_path(&self, name: &str, digest: &Digest) -> String {
        format!(
            "{}/link",
            self.manifest_config_link_container_dir(name, digest)
        )
    }

    pub fn manifest_referrers_dir(&self, name: &str, subject: &Digest) -> String {
        format!(
            "{}/referrers/{}/{}",
            self.manifests_root_dir(name),
            subject.algorithm(),
            subject.hash()
        )
    }

    pub fn manifest_referrer_link_container_dir(
        &self,
        name: &str,
        subject: &Digest,
        referrer: &Digest,
    ) -> String {
        format!(
            "{}/{}/{}",
            self.manifest_referrers_dir(name, subject),
            referrer.algorithm(),
            referrer.hash()
        )
    }

    pub fn manifest_referrer_link_path(
        &self,
        name: &str,
        subject: &Digest,
        referrer: &Digest,
    ) -> String {
        format!(
            "{}/link",
            self.manifest_referrer_link_container_dir(name, subject, referrer)
        )
    }

    pub fn manifest_tags_dir(&self, namespace: &str) -> String {
        format!("{}/tags", self.manifests_root_dir(namespace))
    }

    pub fn manifest_tag_link_container_dir(&self, namespace: &str, tag: &str) -> String {
        format!("{}/tags/{tag}", self.manifests_root_dir(namespace))
    }

    pub fn manifest_tag_link_parent_dir(&self, namespace: &str, tag: &str) -> String {
        format!(
            "{}/current",
            self.manifest_tag_link_container_dir(namespace, tag)
        )
    }

    pub fn manifest_tag_link_path(&self, namespace: &str, tag: &str) -> String {
        format!("{}/link", self.manifest_tag_link_parent_dir(namespace, tag))
    }

    pub fn get_link_path(&self, reference: &BlobLink, name: &str) -> String {
        match reference {
            BlobLink::Tag(tag) => self.manifest_tag_link_path(name, tag),
            BlobLink::Digest(digest) => self.manifest_revisions_link_path(name, digest),
            BlobLink::Layer(digest) => self.manifest_layer_link_path(name, digest),
            BlobLink::Config(digest) => self.manifest_config_link_path(name, digest),
            BlobLink::Referrer(subject, referrer) => {
                self.manifest_referrer_link_path(name, subject, referrer)
            }
        }
    }

    pub fn get_link_container_path(&self, reference: &BlobLink, name: &str) -> String {
        match reference {
            BlobLink::Tag(tag) => self.manifest_tag_link_container_dir(name, tag),
            BlobLink::Digest(digest) => self.manifest_revisions_link_container_dir(name, digest),
            BlobLink::Layer(digest) => self.manifest_layer_link_container_dir(name, digest),
            BlobLink::Config(digest) => self.manifest_config_link_container_dir(name, digest),
            BlobLink::Referrer(subject, referrer) => {
                self.manifest_referrer_link_container_dir(name, subject, referrer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::oci_types::Digest;

    #[test]
    fn test_no_prefix() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(builder.blobs_root_dir(), "v2/blobs");
    }

    #[test]
    fn test_prefix() {
        let builder = DataPathBuilder::new("prefix".to_string());
        assert_eq!(builder.blobs_root_dir(), "prefix/v2/blobs");
    }

    #[test]
    fn test_blob_container_dir() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.blob_container_dir(&digest),
            "v2/blobs/sha256/12/1234567890abcdef"
        );
    }

    #[test]
    fn test_blob_path() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.blob_path(&digest),
            "v2/blobs/sha256/12/1234567890abcdef/data"
        );
    }

    #[test]
    fn test_blob_index_path() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.blob_index_path(&digest),
            "v2/blobs/sha256/12/1234567890abcdef/index.json"
        );
    }

    #[test]
    fn test_repository_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(builder.repository_dir(), "v2/repositories");
    }

    #[test]
    fn test_uploads_root_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.uploads_root_dir("namespace"),
            "v2/repositories/namespace/_uploads"
        );
    }

    #[test]
    fn test_upload_container_path() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.upload_container_path("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid"
        );
    }

    #[test]
    fn test_upload_path() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.upload_path("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid/data"
        );
    }

    #[test]
    fn test_upload_staged_container_path() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.upload_staged_container_path("namespace", "uuid", 0),
            "v2/repositories/namespace/_uploads/uuid/staged/0"
        );
    }

    #[test]
    fn test_upload_hash_context_container_path() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.upload_hash_context_container_path("namespace", "uuid", "sha256"),
            "v2/repositories/namespace/_uploads/uuid/hashstates/sha256"
        );
    }

    #[test]
    fn test_upload_hash_context_path() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.upload_hash_context_path("namespace", "uuid", "sha256", 0),
            "v2/repositories/namespace/_uploads/uuid/hashstates/sha256/0"
        );
    }

    #[test]
    fn test_upload_start_date_container_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.upload_start_date_container_dir("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid"
        );
    }

    #[test]
    fn test_upload_start_date_path() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.upload_start_date_path("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid/startedat"
        );
    }

    #[test]
    fn test_manifests_root_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.manifests_root_dir("namespace"),
            "v2/repositories/namespace/_manifests"
        );
    }

    #[test]
    fn test_manifest_revisions_link_root_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.manifest_revisions_link_root_dir("name", "sha256"),
            "v2/repositories/name/_manifests/revisions/sha256"
        );
    }

    #[test]
    fn test_manifest_revisions_link_container_dir() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_revisions_link_container_dir("name", &digest),
            "v2/repositories/name/_manifests/revisions/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_revisions_link_path() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_revisions_link_path("name", &digest),
            "v2/repositories/name/_manifests/revisions/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_layers_root_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.layers_root_dir("namespace"),
            "v2/repositories/namespace/_layers"
        );
    }

    #[test]
    fn test_manifest_layer_link_container_dir() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_layer_link_container_dir("name", &digest),
            "v2/repositories/name/_layers/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_layer_link_path() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_layer_link_path("name", &digest),
            "v2/repositories/name/_layers/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_config_root_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.config_root_dir("namespace"),
            "v2/repositories/namespace/_config"
        );
    }

    #[test]
    fn test_manifest_config_link_container_dir() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_config_link_container_dir("name", &digest),
            "v2/repositories/name/_config/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_config_link_path() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_config_link_path("name", &digest),
            "v2/repositories/name/_config/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_manifest_referrers_dir() {
        let builder = DataPathBuilder::new(String::new());
        let subject = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_referrers_dir("name", &subject),
            "v2/repositories/name/_manifests/referrers/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_referrer_link_container_dir() {
        let builder = DataPathBuilder::new(String::new());
        let subject = Digest::Sha256("1234567890abcdef".to_string());
        let referrer = Digest::Sha256("abcdef1234567890".to_string());
        assert_eq!(builder.manifest_referrer_link_container_dir("name", &subject, &referrer), "v2/repositories/name/_manifests/referrers/sha256/1234567890abcdef/sha256/abcdef1234567890");
    }

    #[test]
    fn test_manifest_referrer_link_path() {
        let builder = DataPathBuilder::new(String::new());
        let subject = Digest::Sha256("1234567890abcdef".to_string());
        let referrer = Digest::Sha256("abcdef1234567890".to_string());
        assert_eq!(builder.manifest_referrer_link_path("name", &subject, &referrer), "v2/repositories/name/_manifests/referrers/sha256/1234567890abcdef/sha256/abcdef1234567890/link");
    }

    #[test]
    fn test_manifest_tags_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.manifest_tags_dir("namespace"),
            "v2/repositories/namespace/_manifests/tags"
        );
    }

    #[test]
    fn test_manifest_tag_link_container_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.manifest_tag_link_container_dir("namespace", "tag"),
            "v2/repositories/namespace/_manifests/tags/tag"
        );
    }

    #[test]
    fn test_manifest_tag_link_parent_dir() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.manifest_tag_link_parent_dir("namespace", "tag"),
            "v2/repositories/namespace/_manifests/tags/tag/current"
        );
    }

    #[test]
    fn test_manifest_tag_link_path() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.manifest_tag_link_path("namespace", "tag"),
            "v2/repositories/namespace/_manifests/tags/tag/current/link"
        );
    }

    #[test]
    fn test_get_link_path() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.get_link_path(&BlobLink::Digest(digest), "name"),
            "v2/repositories/name/_manifests/revisions/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_get_link_container_path() {
        let builder = DataPathBuilder::new(String::new());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.get_link_container_path(&BlobLink::Digest(digest), "name"),
            "v2/repositories/name/_manifests/revisions/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_get_link_path_tag() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.get_link_path(&BlobLink::Tag("tag".to_string()), "name"),
            "v2/repositories/name/_manifests/tags/tag/current/link"
        );
    }

    #[test]
    fn test_get_link_container_path_tag() {
        let builder = DataPathBuilder::new(String::new());
        assert_eq!(
            builder.get_link_container_path(&BlobLink::Tag("tag".to_string()), "name"),
            "v2/repositories/name/_manifests/tags/tag"
        );
    }
}
