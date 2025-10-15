use crate::oci::Digest;
use crate::registry::metadata_store::link_kind::LinkKind;

pub fn blobs_root_dir() -> String {
    "v2/blobs".to_string()
}

pub fn blob_container_dir(digest: &Digest) -> String {
    format!(
        "{}/{}/{}/{}",
        blobs_root_dir(),
        digest.algorithm(),
        digest.hash_prefix(),
        digest.hash()
    )
}

pub fn blob_path(digest: &Digest) -> String {
    format!("{}/data", blob_container_dir(digest))
}

pub fn blob_index_path(digest: &Digest) -> String {
    format!("{}/index.json", blob_container_dir(digest))
}

pub fn repository_dir() -> String {
    "v2/repositories".to_string()
}

pub fn uploads_root_dir(namespace: &str) -> String {
    format!("{}/{namespace}/_uploads", repository_dir())
}

pub fn upload_container_path(name: &str, uuid: &str) -> String {
    format!("{}/{uuid}", uploads_root_dir(name))
}

pub fn upload_path(name: &str, uuid: &str) -> String {
    format!("{}/data", upload_container_path(name, uuid))
}

pub fn upload_staged_container_path(name: &str, uuid: &str, offset: u64) -> String {
    format!("{}/{uuid}/staged/{offset}", uploads_root_dir(name))
}

pub fn upload_hash_context_container_path(name: &str, uuid: &str, algorithm: &str) -> String {
    format!("{}/{uuid}/hashstates/{algorithm}", uploads_root_dir(name),)
}

pub fn upload_hash_context_path(name: &str, uuid: &str, algorithm: &str, offset: u64) -> String {
    format!(
        "{}/{offset}",
        upload_hash_context_container_path(name, uuid, algorithm)
    )
}

pub fn upload_start_date_container_dir(name: &str, uuid: &str) -> String {
    format!("{}/{uuid}", uploads_root_dir(name))
}

pub fn upload_start_date_path(name: &str, uuid: &str) -> String {
    format!("{}/startedat", upload_start_date_container_dir(name, uuid),)
}

pub fn manifests_root_dir(namespace: &str) -> String {
    format!("{}/{namespace}/_manifests", repository_dir())
}

pub fn manifest_revisions_link_root_dir(name: &str, algorithm: &str) -> String {
    format!("{}/revisions/{algorithm}", manifests_root_dir(name))
}

pub fn manifest_revisions_link_container_dir(name: &str, digest: &Digest) -> String {
    format!(
        "{}/{}",
        manifest_revisions_link_root_dir(name, digest.algorithm()),
        digest.hash(),
    )
}

pub fn manifest_revisions_link_path(name: &str, digest: &Digest) -> String {
    format!(
        "{}/link",
        manifest_revisions_link_container_dir(name, digest)
    )
}

pub fn manifest_tag_link_container_dir(name: &str, tag: &str) -> String {
    format!("{}/tags/{tag}", manifests_root_dir(name))
}

pub fn manifest_tag_current_dir(name: &str, tag: &str) -> String {
    format!("{}/current", manifest_tag_link_container_dir(name, tag))
}

#[cfg(test)]
pub fn manifest_tag_index_dir(name: &str, tag: &str) -> String {
    format!("{}/index", manifest_tag_link_container_dir(name, tag))
}

#[cfg(test)]
pub fn manifest_tag_index_path(name: &str, tag: &str, digest: &Digest) -> String {
    format!(
        "{}/{}/{}",
        manifest_tag_index_dir(name, tag),
        digest.algorithm(),
        digest.hash()
    )
}

pub fn manifest_tag_link_path(name: &str, tag: &str) -> String {
    format!("{}/link", manifest_tag_current_dir(name, tag))
}

pub fn layers_root_dir(namespace: &str) -> String {
    format!("{}/{namespace}/_layers", repository_dir())
}

pub fn manifest_layer_link_root_dir(name: &str, algorithm: &str) -> String {
    format!("{}/{algorithm}", layers_root_dir(name))
}

pub fn manifest_layer_link_container_dir(name: &str, digest: &Digest) -> String {
    format!(
        "{}/{}",
        manifest_layer_link_root_dir(name, digest.algorithm()),
        digest.hash()
    )
}

pub fn manifest_layer_link_path(name: &str, digest: &Digest) -> String {
    format!("{}/link", manifest_layer_link_container_dir(name, digest))
}

pub fn manifest_config_root_dir(namespace: &str) -> String {
    format!("{}/{namespace}/_config", repository_dir())
}

pub fn manifest_config_link_root_dir(name: &str, algorithm: &str) -> String {
    format!("{}/{algorithm}", manifest_config_root_dir(name))
}

pub fn manifest_config_link_container_dir(name: &str, digest: &Digest) -> String {
    format!(
        "{}/{}",
        manifest_config_link_root_dir(name, digest.algorithm()),
        digest.hash()
    )
}

pub fn manifest_config_link_path(name: &str, digest: &Digest) -> String {
    format!("{}/link", manifest_config_link_container_dir(name, digest))
}

pub fn manifest_referrers_dir(name: &str, subject: &Digest) -> String {
    format!(
        "{}/referrers/{}/{}",
        manifests_root_dir(name),
        subject.algorithm(),
        subject.hash()
    )
}

pub fn manifest_referrer_link_container_dir(
    name: &str,
    subject: &Digest,
    referrer: &Digest,
) -> String {
    format!(
        "{}/{}/{}",
        manifest_referrers_dir(name, subject),
        referrer.algorithm(),
        referrer.hash()
    )
}

pub fn manifest_referrer_link_path(name: &str, subject: &Digest, referrer: &Digest) -> String {
    format!(
        "{}/link",
        manifest_referrer_link_container_dir(name, subject, referrer)
    )
}

pub fn manifest_tags_dir(namespace: &str) -> String {
    format!("{}/tags", manifests_root_dir(namespace))
}

pub fn get_link_path(reference: &LinkKind, name: &str) -> String {
    match reference {
        LinkKind::Tag(tag) => manifest_tag_link_path(name, tag),
        LinkKind::Digest(digest) => manifest_revisions_link_path(name, digest),
        LinkKind::Layer(digest) => manifest_layer_link_path(name, digest),
        LinkKind::Config(digest) => manifest_config_link_path(name, digest),
        LinkKind::Referrer(subject, referrer) => {
            manifest_referrer_link_path(name, subject, referrer)
        }
    }
}

pub fn get_link_container_path(reference: &LinkKind, name: &str) -> String {
    match reference {
        LinkKind::Tag(tag) => manifest_tag_link_container_dir(name, tag),
        LinkKind::Digest(digest) => manifest_revisions_link_container_dir(name, digest),
        LinkKind::Layer(digest) => manifest_layer_link_container_dir(name, digest),
        LinkKind::Config(digest) => manifest_config_link_container_dir(name, digest),
        LinkKind::Referrer(subject, referrer) => {
            manifest_referrer_link_container_dir(name, subject, referrer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::Digest;

    #[test]
    fn test_no_prefix() {
        assert_eq!(blobs_root_dir(), "v2/blobs");
    }

    #[test]
    fn test_blob_container_dir() {
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            blob_container_dir(&digest),
            "v2/blobs/sha256/12/1234567890abcdef"
        );
    }

    #[test]
    fn test_blob_path() {
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            blob_path(&digest),
            "v2/blobs/sha256/12/1234567890abcdef/data"
        );
    }

    #[test]
    fn test_blob_index_path() {
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            blob_index_path(&digest),
            "v2/blobs/sha256/12/1234567890abcdef/index.json"
        );
    }

    #[test]
    fn test_repository_dir() {
        assert_eq!(repository_dir(), "v2/repositories");
    }

    #[test]
    fn test_uploads_root_dir() {
        assert_eq!(
            uploads_root_dir("namespace"),
            "v2/repositories/namespace/_uploads"
        );
    }

    #[test]
    fn test_upload_container_path() {
        assert_eq!(
            upload_container_path("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid"
        );
    }

    #[test]
    fn test_upload_path() {
        assert_eq!(
            upload_path("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid/data"
        );
    }

    #[test]
    fn test_upload_staged_container_path() {
        assert_eq!(
            upload_staged_container_path("namespace", "uuid", 0),
            "v2/repositories/namespace/_uploads/uuid/staged/0"
        );
    }

    #[test]
    fn test_upload_hash_context_container_path() {
        assert_eq!(
            upload_hash_context_container_path("namespace", "uuid", "sha256"),
            "v2/repositories/namespace/_uploads/uuid/hashstates/sha256"
        );
    }

    #[test]
    fn test_upload_hash_context_path() {
        assert_eq!(
            upload_hash_context_path("namespace", "uuid", "sha256", 0),
            "v2/repositories/namespace/_uploads/uuid/hashstates/sha256/0"
        );
    }

    #[test]
    fn test_upload_start_date_container_dir() {
        assert_eq!(
            upload_start_date_container_dir("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid"
        );
    }

    #[test]
    fn test_upload_start_date_path() {
        assert_eq!(
            upload_start_date_path("namespace", "uuid"),
            "v2/repositories/namespace/_uploads/uuid/startedat"
        );
    }

    #[test]
    fn test_manifests_root_dir() {
        assert_eq!(
            manifests_root_dir("namespace"),
            "v2/repositories/namespace/_manifests"
        );
    }

    #[test]
    fn test_manifest_revisions_link_root_dir() {
        assert_eq!(
            manifest_revisions_link_root_dir("namespace", "sha256"),
            "v2/repositories/namespace/_manifests/revisions/sha256"
        );
    }

    #[test]
    fn test_manifest_revisions_link_container_dir() {
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            manifest_revisions_link_container_dir("namespace", &digest),
            "v2/repositories/namespace/_manifests/revisions/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_revisions_link_path() {
        let digest = Digest::Sha256("abcdef123456".to_string());
        assert_eq!(
            manifest_revisions_link_path("namespace", &digest),
            "v2/repositories/namespace/_manifests/revisions/sha256/abcdef123456/link"
        );
    }

    #[test]
    fn test_manifest_tag_link_container_dir() {
        assert_eq!(
            manifest_tag_link_container_dir("namespace", "latest"),
            "v2/repositories/namespace/_manifests/tags/latest"
        );
    }

    #[test]
    fn test_manifest_tag_current_dir() {
        assert_eq!(
            manifest_tag_current_dir("namespace", "latest"),
            "v2/repositories/namespace/_manifests/tags/latest/current"
        );
    }

    #[test]
    fn test_manifest_tag_index_dir() {
        assert_eq!(
            manifest_tag_index_dir("namespace", "latest"),
            "v2/repositories/namespace/_manifests/tags/latest/index"
        );
    }

    #[test]
    fn test_manifest_tag_index_path() {
        let digest = Digest::Sha256("abc123".to_string());
        assert_eq!(
            manifest_tag_index_path("namespace", "latest", &digest),
            "v2/repositories/namespace/_manifests/tags/latest/index/sha256/abc123"
        );
    }

    #[test]
    fn test_manifest_tag_link_path() {
        assert_eq!(
            manifest_tag_link_path("namespace", "latest"),
            "v2/repositories/namespace/_manifests/tags/latest/current/link"
        );
    }

    #[test]
    fn test_layers_root_dir() {
        assert_eq!(
            layers_root_dir("namespace"),
            "v2/repositories/namespace/_layers"
        );
    }

    #[test]
    fn test_manifest_layer_link_root_dir() {
        assert_eq!(
            manifest_layer_link_root_dir("namespace", "sha256"),
            "v2/repositories/namespace/_layers/sha256"
        );
    }

    #[test]
    fn test_manifest_layer_link_container_dir() {
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            manifest_layer_link_container_dir("namespace", &digest),
            "v2/repositories/namespace/_layers/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_layer_link_path() {
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            manifest_layer_link_path("namespace", &digest),
            "v2/repositories/namespace/_layers/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_manifest_config_root_dir() {
        assert_eq!(
            manifest_config_root_dir("namespace"),
            "v2/repositories/namespace/_config"
        );
    }

    #[test]
    fn test_manifest_config_link_root_dir() {
        assert_eq!(
            manifest_config_link_root_dir("namespace", "sha256"),
            "v2/repositories/namespace/_config/sha256"
        );
    }

    #[test]
    fn test_manifest_config_link_container_dir() {
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            manifest_config_link_container_dir("namespace", &digest),
            "v2/repositories/namespace/_config/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_config_link_path() {
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            manifest_config_link_path("namespace", &digest),
            "v2/repositories/namespace/_config/sha256/1234567890abcdef/link"
        );
    }

    #[test]
    fn test_manifest_referrers_dir() {
        let subject = Digest::Sha256("1234567890abcdef".to_string());
        assert_eq!(
            manifest_referrers_dir("namespace", &subject),
            "v2/repositories/namespace/_manifests/referrers/sha256/1234567890abcdef"
        );
    }

    #[test]
    fn test_manifest_referrer_link_container_dir() {
        let subject = Digest::Sha256("subject789".to_string());
        let referrer = Digest::Sha256("referrer012".to_string());
        assert_eq!(
            manifest_referrer_link_container_dir("namespace", &subject, &referrer),
            "v2/repositories/namespace/_manifests/referrers/sha256/subject789/sha256/referrer012"
        );
    }

    #[test]
    fn test_manifest_referrer_link_path() {
        let subject = Digest::Sha256("subject789".to_string());
        let referrer = Digest::Sha256("referrer012".to_string());
        assert_eq!(
            manifest_referrer_link_path("namespace", &subject, &referrer),
            "v2/repositories/namespace/_manifests/referrers/sha256/subject789/sha256/referrer012/link"
        );
    }

    #[test]
    fn test_manifest_tags_dir() {
        assert_eq!(
            manifest_tags_dir("namespace"),
            "v2/repositories/namespace/_manifests/tags"
        );
    }

    #[test]
    fn test_get_link_path() {
        let tag_ref = LinkKind::Tag("v1.0".to_string());
        assert_eq!(
            get_link_path(&tag_ref, "namespace"),
            "v2/repositories/namespace/_manifests/tags/v1.0/current/link"
        );

        let digest = Digest::Sha256("digest123".to_string());
        let digest_ref = LinkKind::Digest(digest.clone());
        assert_eq!(
            get_link_path(&digest_ref, "namespace"),
            "v2/repositories/namespace/_manifests/revisions/sha256/digest123/link"
        );

        let layer_ref = LinkKind::Layer(digest.clone());
        assert_eq!(
            get_link_path(&layer_ref, "namespace"),
            "v2/repositories/namespace/_layers/sha256/digest123/link"
        );

        let config_ref = LinkKind::Config(digest.clone());
        assert_eq!(
            get_link_path(&config_ref, "namespace"),
            "v2/repositories/namespace/_config/sha256/digest123/link"
        );

        let subject = Digest::Sha256("subject456".to_string());
        let referrer = Digest::Sha256("referrer789".to_string());
        let referrer_ref = LinkKind::Referrer(subject.clone(), referrer.clone());
        assert_eq!(
            get_link_path(&referrer_ref, "namespace"),
            "v2/repositories/namespace/_manifests/referrers/sha256/subject456/sha256/referrer789/link"
        );
    }

    #[test]
    fn test_get_link_container_path() {
        let tag_ref = LinkKind::Tag("v1.0".to_string());
        assert_eq!(
            get_link_container_path(&tag_ref, "namespace"),
            "v2/repositories/namespace/_manifests/tags/v1.0"
        );

        let digest = Digest::Sha256("digest123".to_string());
        let digest_ref = LinkKind::Digest(digest.clone());
        assert_eq!(
            get_link_container_path(&digest_ref, "namespace"),
            "v2/repositories/namespace/_manifests/revisions/sha256/digest123"
        );

        let layer_ref = LinkKind::Layer(digest.clone());
        assert_eq!(
            get_link_container_path(&layer_ref, "namespace"),
            "v2/repositories/namespace/_layers/sha256/digest123"
        );

        let config_ref = LinkKind::Config(digest.clone());
        assert_eq!(
            get_link_container_path(&config_ref, "namespace"),
            "v2/repositories/namespace/_config/sha256/digest123"
        );

        let subject = Digest::Sha256("subject456".to_string());
        let referrer = Digest::Sha256("referrer789".to_string());
        let referrer_ref = LinkKind::Referrer(subject.clone(), referrer.clone());
        assert_eq!(
            get_link_container_path(&referrer_ref, "namespace"),
            "v2/repositories/namespace/_manifests/referrers/sha256/subject456/sha256/referrer789"
        );
    }
}
