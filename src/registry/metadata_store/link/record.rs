//! Immutable revision and referrer records.
//!
//! A stored manifest is one never-mutated record at
//! [`NamespaceKeys::revision_record_path`] whose existence makes the digest
//! resolvable; a referrer is one record per (subject, referrer) whose body is
//! the referring manifest's descriptor.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use angos_oci::{Descriptor, Digest, MediaType, Namespace};
use angos_storage::Error as StorageError;

use crate::registry::keys::NamespaceKeys;
use crate::registry::metadata_store::{access_time::put_access_entry, mutation::Mutation};
use crate::registry::{
    Error,
    metadata_store::{LinkMetadata, MetadataStore},
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
            media_type: self.media_type,
            descriptor: None,
        }
    }
}

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
        key: namespace.revision_record_path(digest),
        body: Bytes::from(body),
    })
}

/// The body is the referring manifest's descriptor, or an empty object when
/// the push carried none (the listing needs only the key).
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
        key: namespace.referrer_record_path(subject, referrer),
        body: Bytes::from(body),
    })
}

impl MetadataStore {
    /// Resolve a manifest revision to link-shaped metadata.
    pub async fn resolve_revision(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<LinkMetadata, Error> {
        let key = namespace.revision_record_path(digest);
        match self.object_store().get(&key).await {
            Ok(body) => {
                let record: RevisionRecord = serde_json::from_slice(&body)
                    .map_err(|e| Error::Internal(format!("corrupt revision record {key}: {e}")))?;
                Ok(record.into_metadata(digest))
            }
            Err(StorageError::NotFound) => Err(Error::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Resolve a referrer back-link to its stored descriptor.
    pub async fn resolve_referrer(
        &self,
        namespace: &Namespace,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<LinkMetadata, Error> {
        let key = namespace.referrer_record_path(subject, referrer);
        match self.object_store().get(&key).await {
            Ok(body) => Ok(LinkMetadata {
                target: referrer.clone(),
                created_at: None,
                accessed_at: None,
                media_type: None,
                descriptor: serde_json::from_slice::<Descriptor>(&body).ok(),
            }),
            Err(StorageError::NotFound) => Err(Error::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// The revision's advisory last-pull timestamp: its newest access entry.
    pub async fn read_revision_access_time(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        self.newest_access_time(&namespace.revision_atime_entry_dir(digest))
            .await
    }

    /// Append one access entry naming `client` to the revision's atime
    /// directory, a plain put with no read.
    pub async fn write_revision_access_time(
        &self,
        namespace: &Namespace,
        digest: &Digest,
        client: &str,
    ) -> Result<(), Error> {
        put_access_entry(
            self.object_store(),
            &namespace.revision_atime_entry_dir(digest),
            client,
        )
        .await
    }
}
