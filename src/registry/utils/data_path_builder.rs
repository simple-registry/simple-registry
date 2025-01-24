use crate::oci::Digest;
use crate::registry::utils::DataLink;

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
        format!("{}/{}/_uploads", self.repository_dir(), namespace)
    }

    pub fn upload_container_path(&self, name: &str, uuid: &str) -> String {
        format!("{}/{}", self.uploads_root_dir(name), uuid)
    }

    pub fn upload_path(&self, name: &str, uuid: &str) -> String {
        format!("{}/data", self.upload_container_path(name, uuid))
    }

    pub fn upload_staged_container_path(&self, name: &str, uuid: &str, offset: u64) -> String {
        format!("{}/{}/staged/{}", self.uploads_root_dir(name), uuid, offset)
    }

    pub fn upload_hash_context_container_path(
        &self,
        name: &str,
        uuid: &str,
        algorithm: &str,
    ) -> String {
        format!(
            "{}/{}/hashstates/{}",
            self.uploads_root_dir(name),
            uuid,
            algorithm
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
            "{}/{}",
            self.upload_hash_context_container_path(name, uuid, algorithm),
            offset
        )
    }

    pub fn upload_start_date_container_dir(&self, name: &str, uuid: &str) -> String {
        format!("{}/{}", self.uploads_root_dir(name), uuid)
    }

    pub fn upload_start_date_path(&self, name: &str, uuid: &str) -> String {
        format!(
            "{}/startedat",
            self.upload_start_date_container_dir(name, uuid),
        )
    }

    pub fn manifests_root_dir(&self, namespace: &str) -> String {
        format!("{}/{}/_manifests", self.repository_dir(), namespace)
    }

    pub fn manifest_revisions_link_root_dir(&self, name: &str, algorithm: &str) -> String {
        format!("{}/revisions/{}", self.manifests_root_dir(name), algorithm)
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
        format!("{}/{}/_layers", self.repository_dir(), namespace)
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
        format!("{}/{}/_config", self.repository_dir(), namespace)
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
        format!("{}/tags/{}", self.manifests_root_dir(namespace), tag)
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

    pub fn get_link_path(&self, reference: &DataLink, name: &str) -> String {
        match reference {
            DataLink::Tag(tag) => self.manifest_tag_link_path(name, tag),
            DataLink::Digest(digest) => self.manifest_revisions_link_path(name, digest),
            DataLink::Layer(digest) => self.manifest_layer_link_path(name, digest),
            DataLink::Config(digest) => self.manifest_config_link_path(name, digest),
            DataLink::Referrer(subject, referrer) => {
                self.manifest_referrer_link_path(name, subject, referrer)
            }
        }
    }

    pub fn get_link_parent_path(&self, reference: &DataLink, name: &str) -> String {
        match reference {
            DataLink::Tag(tag) => self.manifest_tag_link_parent_dir(name, tag),
            _ => self.get_link_container_path(reference, name),
        }
    }

    pub fn get_link_container_path(&self, reference: &DataLink, name: &str) -> String {
        match reference {
            DataLink::Tag(tag) => self.manifest_tag_link_container_dir(name, tag),
            DataLink::Digest(digest) => self.manifest_revisions_link_container_dir(name, digest),
            DataLink::Layer(digest) => self.manifest_layer_link_container_dir(name, digest),
            DataLink::Config(digest) => self.manifest_config_link_container_dir(name, digest),
            DataLink::Referrer(subject, referrer) => {
                self.manifest_referrer_link_container_dir(name, subject, referrer)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::oci::Digest;

    #[test]
    fn test_no_prefix() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(builder.blobs_root_dir(), "v2/blobs");
    }

    #[test]
    fn test_prefix() {
        let builder = DataPathBuilder::new("prefix".to_string());
        assert_eq!(builder.blobs_root_dir(), "prefix/v2/blobs");
    }

    #[test]
    fn test_blob_container_dir() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.blob_container_dir(&digest),
            "v2/blobs/sha256/12/1234567890abcdef"
        );
    }

    #[test]
    fn test_blob_path() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.blob_path(&digest),
            "v2/blobs/sha256/12/1234567890abcdef/data"
        );
    }

    #[test]
    fn test_blob_index_path() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.blob_index_path(&digest),
            "v2/blobs/sha256/12/1234567890abcdef/index.json"
        );
    }

    #[test]
    fn test_repository_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(builder.repository_dir(), "v2/repositories");
    }

    #[test]
    fn test_uploads_root_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.uploads_root_dir("namespace"),
            "v2/repositories/namespace/_uploads"
        );
    }

    #[test]
    fn test_upload_container_path() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.upload_container_path("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid"
        );
    }

    #[test]
    fn test_upload_path() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.upload_path("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid/data"
        );
    }

    #[test]
    fn test_upload_staged_container_path() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.upload_staged_container_path("namespace", "uuid", 0),
            "v2/repositories/namespace/_uploads/uuid/staged/0"
        );
    }

    #[test]
    fn test_upload_hash_context_container_path() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.upload_hash_context_container_path("namespace", "uuid", "sha256"),
            "v2/repositories/namespace/_uploads/uuid/hashstates/sha256"
        );
    }

    #[test]
    fn test_upload_hash_context_path() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.upload_hash_context_path("namespace", "uuid", "sha256", 0),
            "v2/repositories/namespace/_uploads/uuid/hashstates/sha256/0"
        );
    }

    #[test]
    fn test_upload_start_date_container_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.upload_start_date_container_dir("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid"
        );
    }

    #[test]
    fn test_upload_start_date_path() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.upload_start_date_path("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid/startedat"
        );
    }

    #[test]
    fn test_manifests_root_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.manifests_root_dir("namespace"),
            "v2/repositories/namespace/_manifests"
        );
    }

    #[test]
    fn test_manifest_revisions_link_root_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.manifest_revisions_link_root_dir("name", "sha256"),
            "v2/repositories/name/_manifests/revisions/sha256"
        );
    }

    #[test]
    fn test_manifest_revisions_link_container_dir() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_revisions_link_container_dir("name", &digest),
            "v2/repositories/name/_manifests/revisions/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_revisions_link_path() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_revisions_link_path("name", &digest),
            "v2/repositories/name/_manifests/revisions/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_layers_root_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.layers_root_dir("namespace"),
            "v2/repositories/namespace/_layers"
        );
    }

    #[test]
    fn test_manifest_layer_link_container_dir() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_layer_link_container_dir("name", &digest),
            "v2/repositories/name/_layers/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_layer_link_path() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_layer_link_path("name", &digest),
            "v2/repositories/name/_layers/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_config_root_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.config_root_dir("namespace"),
            "v2/repositories/namespace/_config"
        );
    }

    #[test]
    fn test_manifest_config_link_container_dir() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_config_link_container_dir("name", &digest),
            "v2/repositories/name/_config/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_config_link_path() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_config_link_path("name", &digest),
            "v2/repositories/name/_config/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_manifest_referrers_dir() {
        let builder = DataPathBuilder::new("".to_string());
        let subject = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.manifest_referrers_dir("name", &subject),
            "v2/repositories/name/_manifests/referrers/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_referrer_link_container_dir() {
        let builder = DataPathBuilder::new("".to_string());
        let subject = Digest::Sha256("1234567890abcdef".to_string());
        let referrer = Digest::Sha256("abcdef1234567890".to_string());
        assert_eq!(builder.manifest_referrer_link_container_dir("name", &subject, &referrer), "v2/repositories/name/_manifests/referrers/sha256/1234567890abcdef/sha256/abcdef1234567890");
    }

    #[test]
    fn test_manifest_referrer_link_path() {
        let builder = DataPathBuilder::new("".to_string());
        let subject = Digest::Sha256("1234567890abcdef".to_string());
        let referrer = Digest::Sha256("abcdef1234567890".to_string());
        assert_eq!(builder.manifest_referrer_link_path("name", &subject, &referrer), "v2/repositories/name/_manifests/referrers/sha256/1234567890abcdef/sha256/abcdef1234567890/link");
    }

    #[test]
    fn test_manifest_tags_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.manifest_tags_dir("namespace"),
            "v2/repositories/namespace/_manifests/tags"
        );
    }

    #[test]
    fn test_manifest_tag_link_container_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.manifest_tag_link_container_dir("namespace", "tag"),
            "v2/repositories/namespace/_manifests/tags/tag"
        );
    }

    #[test]
    fn test_manifest_tag_link_parent_dir() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.manifest_tag_link_parent_dir("namespace", "tag"),
            "v2/repositories/namespace/_manifests/tags/tag/current"
        );
    }

    #[test]
    fn test_manifest_tag_link_path() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.manifest_tag_link_path("namespace", "tag"),
            "v2/repositories/namespace/_manifests/tags/tag/current/link"
        );
    }

    #[test]
    fn test_get_link_path() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.get_link_path(&DataLink::Digest(digest), "name"),
            "v2/repositories/name/_manifests/revisions/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_get_link_parent_path() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.get_link_parent_path(&DataLink::Digest(digest), "name"),
            "v2/repositories/name/_manifests/revisions/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_get_link_container_path() {
        let builder = DataPathBuilder::new("".to_string());
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            builder.get_link_container_path(&DataLink::Digest(digest), "name"),
            "v2/repositories/name/_manifests/revisions/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_get_link_path_tag() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.get_link_path(&DataLink::Tag("tag".to_string()), "name"),
            "v2/repositories/name/_manifests/tags/tag/current/link"
        );
    }

    #[test]
    fn test_get_link_parent_path_tag() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.get_link_parent_path(&DataLink::Tag("tag".to_string()), "name"),
            "v2/repositories/name/_manifests/tags/tag/current"
        );
    }

    #[test]
    fn test_get_link_container_path_tag() {
        let builder = DataPathBuilder::new("".to_string());
        assert_eq!(
            builder.get_link_container_path(&DataLink::Tag("tag".to_string()), "name"),
            "v2/repositories/name/_manifests/tags/tag"
        );
    }
}
