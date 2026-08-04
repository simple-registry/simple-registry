use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{identity::ClientIdentity, oci::Namespace};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum EventKind {
    #[serde(rename = "manifest.push")]
    ManifestPush,
    #[serde(rename = "manifest.pull")]
    ManifestPull,
    #[serde(rename = "manifest.delete")]
    ManifestDelete,
    #[serde(rename = "blob.push")]
    BlobPush,
    #[serde(rename = "blob.pull")]
    BlobPull,
    #[serde(rename = "tag.create")]
    TagCreate,
    #[serde(rename = "tag.delete")]
    TagDelete,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::ManifestPush => "manifest.push",
            EventKind::ManifestPull => "manifest.pull",
            EventKind::ManifestDelete => "manifest.delete",
            EventKind::BlobPush => "blob.push",
            EventKind::BlobPull => "blob.pull",
            EventKind::TagCreate => "tag.create",
            EventKind::TagDelete => "tag.delete",
        }
    }
}

/// Serialized from [`EventKind::as_str`], the same string the
/// `X-Registry-Event` header carries, so the header and the body cannot name
/// one event differently.
impl Serialize for EventKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EventActor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Name of the internal process that performed the operation (for
    /// example `prune` or `cache`). Absent on client-initiated operations,
    /// so subscribers can tell internal processes apart from clients and
    /// from each other.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<String>,
}

impl EventActor {
    /// Actor for an operation performed by the named internal process.
    pub fn internal(process: &str) -> Self {
        Self {
            id: None,
            username: None,
            client_ip: None,
            internal: Some(process.to_string()),
        }
    }

    /// `true` when the operation was client-initiated rather than performed
    /// by an internal process.
    pub fn is_client(&self) -> bool {
        self.internal.is_none()
    }
}

impl From<ClientIdentity> for EventActor {
    fn from(identity: ClientIdentity) -> Self {
        Self {
            id: identity.id,
            username: identity.username,
            client_ip: identity.client_ip,
            internal: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub kind: EventKind,
    pub namespace: Namespace,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<EventActor>,
    pub repository: String,
}

impl Event {
    pub fn new(kind: EventKind, namespace: Namespace, repository: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            kind,
            namespace,
            repository,
            digest: None,
            reference: None,
            tag: None,
            actor: None,
        }
    }

    pub fn digest(mut self, digest: Option<String>) -> Self {
        self.digest = digest;
        self
    }

    pub fn reference(mut self, reference: Option<String>) -> Self {
        self.reference = reference;
        self
    }

    pub fn tag(mut self, tag: Option<String>) -> Self {
        self.tag = tag;
        self
    }

    pub fn actor(mut self, actor: Option<EventActor>) -> Self {
        self.actor = actor;
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{
        event_webhook::event::{EventActor, EventKind},
        identity::ClientIdentity,
    };

    #[test]
    fn event_actor_from_client_identity_with_all_fields() {
        let identity = ClientIdentity {
            id: Some("user-123".to_string()),
            username: Some("alice".to_string()),
            client_ip: Some("192.168.1.1".to_string()),
            ..Default::default()
        };

        let actor = EventActor::from(identity);
        assert_eq!(actor.id, Some("user-123".to_string()));
        assert_eq!(actor.username, Some("alice".to_string()));
        assert_eq!(actor.client_ip, Some("192.168.1.1".to_string()));
        assert_eq!(actor.internal, None);
    }

    #[test]
    fn event_actor_from_client_identity_with_no_fields() {
        let identity = ClientIdentity::default();

        let actor = EventActor::from(identity);
        assert_eq!(actor.id, None);
        assert_eq!(actor.username, None);
        assert_eq!(actor.client_ip, None);
        assert_eq!(actor.internal, None);
    }

    #[test]
    fn event_actor_internal_serializes_only_the_process_name() {
        let actor = EventActor::internal("prune");
        let json = serde_json::to_value(&actor).unwrap();
        assert_eq!(json, serde_json::json!({ "internal": "prune" }));
    }

    /// Every variant must name itself identically in the `X-Registry-Event`
    /// header (`as_str`), in the JSON body, and back through the `serde`
    /// renames, so a subscriber filtering on one never disagrees with the other.
    #[test]
    fn event_kind_names_itself_the_same_way_everywhere() {
        let all = [
            (EventKind::ManifestPush, "manifest.push"),
            (EventKind::ManifestPull, "manifest.pull"),
            (EventKind::ManifestDelete, "manifest.delete"),
            (EventKind::BlobPush, "blob.push"),
            (EventKind::BlobPull, "blob.pull"),
            (EventKind::TagCreate, "tag.create"),
            (EventKind::TagDelete, "tag.delete"),
        ];

        for (kind, wire) in all {
            assert_eq!(kind.as_str(), wire);
            assert_eq!(serde_json::to_value(&kind).unwrap(), json!(wire));
            assert_eq!(
                serde_json::from_value::<EventKind>(json!(wire)).unwrap(),
                kind
            );
        }
    }
}
