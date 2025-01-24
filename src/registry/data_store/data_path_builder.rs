use crate::oci::Digest;
use crate::registry::data_store::data_link::DataLink;

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
            "{}/{}",
            self.manifest_referrers_dir(name, subject),
            referrer
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
