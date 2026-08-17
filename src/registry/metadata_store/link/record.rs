//! Immutable revision and referrer records.
//!
//! A stored manifest is one record at [`path_builder::revision_record_path`]:
//! its existence makes the digest resolvable, its body carries what a HEAD
//! needs, and it never mutates (the advisory last-pull timestamp lives in a
//! sibling atime key). A referrer is one record per (subject, referrer) whose
//! body is the referring manifest's descriptor. Records with no new-shape key
//! fall back to the legacy `link` files, which scrub converts.

use std::collections::HashSet;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use angos_oci::{Descriptor, Digest, MediaType, Namespace};
use angos_tx_engine::{StorageError, transaction::Mutation};

use crate::registry::{
    Error,
    metadata_store::{LinkKind, LinkMetadata, MetadataStore},
    path_builder,
};

/// The stored body of a revision record.
#[derive(Debug, Serialize, Deserialize)]
pub struct RevisionRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<MediaType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

impl RevisionRecord {
    fn into_metadata(self, digest: &Digest) -> LinkMetadata {
        LinkMetadata {
            target: digest.clone(),
            created_at: self.created_at,
            accessed_at: None,
            referenced_by: HashSet::new(),
            media_type: self.media_type,
            descriptor: None,
        }
    }
}

/// The mutation writing one revision record.
pub fn revision_set_mutation(
    namespace: &Namespace,
    digest: &Digest,
    created_at: Option<DateTime<Utc>>,
    media_type: Option<MediaType>,
) -> Result<Mutation, serde_json::Error> {
    let body = serde_json::to_vec(&RevisionRecord {
        media_type,
        created_at,
    })?;
    Ok(Mutation::Put {
        key: path_builder::revision_record_path(namespace, digest),
        body: Bytes::from(body),
        expected: None,
    })
}

/// The mutation writing one referrer record: the referring manifest's
/// descriptor when the push carried one, an empty object otherwise (the
/// listing needs only the key).
pub fn referrer_set_mutation(
    namespace: &Namespace,
    subject: &Digest,
    referrer: &Digest,
    descriptor: Option<&Descriptor>,
) -> Result<Mutation, serde_json::Error> {
    let body = match descriptor {
        Some(descriptor) => serde_json::to_vec(descriptor)?,
        None => b"{}".to_vec(),
    };
    Ok(Mutation::Put {
        key: path_builder::referrer_record_path(namespace, subject, referrer),
        body: Bytes::from(body),
        expected: None,
    })
}

impl MetadataStore {
    /// Resolve a manifest revision to link-shaped metadata: the record first,
    /// the legacy revision link as the fallback.
    pub(crate) async fn resolve_revision(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<LinkMetadata, Error> {
        let key = path_builder::revision_record_path(namespace, digest);
        match self.store().object_store().get(&key).await {
            Ok(body) => {
                let record: RevisionRecord = serde_json::from_slice(&body)
                    .map_err(|e| Error::Internal(format!("corrupt revision record {key}: {e}")))?;
                Ok(record.into_metadata(digest))
            }
            Err(StorageError::NotFound) => {
                self.read_legacy_link(&LinkKind::Digest(digest.clone()), namespace)
                    .await
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Resolve a referrer back-link: the record first (its body is the
    /// referring manifest's descriptor), the legacy link as the fallback.
    pub(crate) async fn resolve_referrer(
        &self,
        namespace: &Namespace,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<LinkMetadata, Error> {
        let key = path_builder::referrer_record_path(namespace, subject, referrer);
        match self.store().object_store().get(&key).await {
            Ok(body) => Ok(LinkMetadata {
                target: referrer.clone(),
                created_at: None,
                accessed_at: None,
                referenced_by: HashSet::new(),
                media_type: None,
                descriptor: serde_json::from_slice::<Descriptor>(&body).ok(),
            }),
            Err(StorageError::NotFound) => {
                self.read_legacy_link(
                    &LinkKind::Referrer {
                        subject: subject.clone(),
                        referrer: referrer.clone(),
                    },
                    namespace,
                )
                .await
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Raw read of a legacy link file, the fallback for a kind whose record
    /// is absent.
    async fn read_legacy_link(
        &self,
        link: &LinkKind,
        namespace: &Namespace,
    ) -> Result<LinkMetadata, Error> {
        let link_path = path_builder::link_path(link, namespace);
        match self.store().object_store().get(&link_path).await {
            Ok(data) => serde_json::from_slice(&data).map_err(|e| Error::Internal(e.to_string())),
            Err(StorageError::NotFound) => Err(Error::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// The revision's advisory last-pull timestamp, from its sibling atime
    /// key.
    pub async fn read_revision_access_time(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        let key = path_builder::revision_atime_path(namespace, digest);
        match self.store().object_store().get(&key).await {
            Ok(raw) => Ok(std::str::from_utf8(&raw)
                .ok()
                .and_then(|text| DateTime::parse_from_rfc3339(text.trim()).ok())
                .map(Into::into)),
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Overwrite the revision's atime key with the current time: advisory, a
    /// plain put with no transaction and no read.
    pub(crate) async fn write_revision_access_time(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<(), Error> {
        let key = path_builder::revision_atime_path(namespace, digest);
        self.store()
            .object_store()
            .put(&key, Bytes::from(Utc::now().to_rfc3339()))
            .await
            .map_err(Error::from)
    }

    /// Convert one legacy revision link into a record, then delete the link.
    /// Record first, so an interruption loses nothing; both halves are
    /// idempotent, and an absent link is a no-op.
    pub async fn convert_legacy_revision_link(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<(), Error> {
        let link = LinkKind::Digest(digest.clone());
        let metadata = match self.read_legacy_link(&link, namespace).await {
            Ok(metadata) => metadata,
            Err(Error::NotFound) => return Ok(()),
            Err(e) => return Err(e),
        };
        let record = serde_json::to_vec(&RevisionRecord {
            media_type: metadata.media_type,
            created_at: metadata.created_at,
        })?;
        self.store()
            .object_store()
            .put(
                &path_builder::revision_record_path(namespace, digest),
                Bytes::from(record),
            )
            .await?;
        self.store()
            .object_store()
            .delete(&path_builder::link_path(&link, namespace))
            .await?;
        self.cache_invalidate(namespace, &link).await;
        Ok(())
    }

    /// Convert one legacy referrer link into a record, then delete the link.
    pub async fn convert_legacy_referrer_link(
        &self,
        namespace: &Namespace,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<(), Error> {
        let link = LinkKind::Referrer {
            subject: subject.clone(),
            referrer: referrer.clone(),
        };
        let metadata = match self.read_legacy_link(&link, namespace).await {
            Ok(metadata) => metadata,
            Err(Error::NotFound) => return Ok(()),
            Err(e) => return Err(e),
        };
        let body = match &metadata.descriptor {
            Some(descriptor) => serde_json::to_vec(descriptor)?,
            None => b"{}".to_vec(),
        };
        self.store()
            .object_store()
            .put(
                &path_builder::referrer_record_path(namespace, subject, referrer),
                Bytes::from(body),
            )
            .await?;
        self.store()
            .object_store()
            .delete(&path_builder::link_path(&link, namespace))
            .await?;
        self.cache_invalidate(namespace, &link).await;
        Ok(())
    }
}
