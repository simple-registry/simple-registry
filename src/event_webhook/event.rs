use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use angos_oci::{Digest, Namespace, Reference, Tag};

use crate::identity::ClientIdentity;

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

/// What an event names. The kind picks the variant, so an event carries
/// exactly the references its kind reports and cannot be built without them.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum EventSubject {
    ManifestPush {
        digest: Digest,
        reference: Reference,
    },
    ManifestPull {
        digest: Digest,
        reference: Reference,
        /// The tag the client pulled by, absent on a pull by digest.
        #[serde(skip_serializing_if = "Option::is_none")]
        tag: Option<Tag>,
    },
    ManifestDelete {
        /// A delete by tag resolves its digest only after the event fires.
        #[serde(skip_serializing_if = "Option::is_none")]
        digest: Option<Digest>,
        reference: Reference,
    },
    BlobPush {
        digest: Digest,
    },
    BlobPull {
        digest: Digest,
    },
    TagCreate {
        digest: Digest,
        reference: Reference,
        tag: Tag,
    },
    /// Emitted only for a delete by tag, which names no digest.
    TagDelete {
        reference: Reference,
        tag: Tag,
    },
}

impl EventSubject {
    pub fn kind(&self) -> EventKind {
        match self {
            EventSubject::ManifestPush { .. } => EventKind::ManifestPush,
            EventSubject::ManifestPull { .. } => EventKind::ManifestPull,
            EventSubject::ManifestDelete { .. } => EventKind::ManifestDelete,
            EventSubject::BlobPush { .. } => EventKind::BlobPush,
            EventSubject::BlobPull { .. } => EventKind::BlobPull,
            EventSubject::TagCreate { .. } => EventKind::TagCreate,
            EventSubject::TagDelete { .. } => EventKind::TagDelete,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    /// Taken from the subject at construction, so the kind a subscriber
    /// filters on and the references it reads always describe one operation.
    kind: EventKind,
    pub namespace: Namespace,
    #[serde(flatten)]
    subject: EventSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<EventActor>,
    pub repository: String,
}

impl Event {
    fn new(
        subject: EventSubject,
        namespace: Namespace,
        repository: String,
        actor: Option<EventActor>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            kind: subject.kind(),
            namespace,
            subject,
            actor,
            repository,
        }
    }

    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    /// The `ManifestDelete` event a delete emits, plus a `TagDelete` when the
    /// reference is a tag. Only a by-digest delete names a digest, since a
    /// delete by tag resolves one after the events fire.
    pub fn delete_manifest(
        namespace: &Namespace,
        repository: &str,
        reference: &Reference,
        actor: Option<&EventActor>,
    ) -> Vec<Self> {
        let event = |subject| {
            Self::new(
                subject,
                namespace.clone(),
                repository.to_string(),
                actor.cloned(),
            )
        };
        match reference {
            Reference::Digest(digest) => vec![event(EventSubject::ManifestDelete {
                digest: Some(digest.clone()),
                reference: reference.clone(),
            })],
            Reference::Tag(tag) => vec![
                event(EventSubject::ManifestDelete {
                    digest: None,
                    reference: reference.clone(),
                }),
                event(EventSubject::TagDelete {
                    reference: reference.clone(),
                    tag: tag.clone(),
                }),
            ],
        }
    }

    /// The `ManifestPull` event a served `GET` emits. It names the tag the
    /// client pulled by, which a pull by digest does not have.
    pub fn pull_manifest(
        namespace: &Namespace,
        repository: &str,
        digest: &Digest,
        reference: &Reference,
        actor: Option<&EventActor>,
    ) -> Self {
        Self::new(
            EventSubject::ManifestPull {
                digest: digest.clone(),
                reference: reference.clone(),
                tag: reference.as_tag().cloned(),
            },
            namespace.clone(),
            repository.to_string(),
            actor.cloned(),
        )
    }

    /// The `BlobPush` event an upload completion, a cross-repo mount or a
    /// cache fill emits.
    pub fn push_blob(
        namespace: &Namespace,
        repository: &str,
        digest: &Digest,
        actor: Option<&EventActor>,
    ) -> Self {
        Self::new(
            EventSubject::BlobPush {
                digest: digest.clone(),
            },
            namespace.clone(),
            repository.to_string(),
            actor.cloned(),
        )
    }

    /// The `BlobPull` event a served `GET` emits.
    pub fn pull_blob(
        namespace: &Namespace,
        repository: &str,
        digest: &Digest,
        actor: Option<&EventActor>,
    ) -> Self {
        Self::new(
            EventSubject::BlobPull {
                digest: digest.clone(),
            },
            namespace.clone(),
            repository.to_string(),
            actor.cloned(),
        )
    }

    /// The `ManifestPush` event alone, for a store that creates no tag.
    pub fn push_manifest(
        namespace: &Namespace,
        repository: &str,
        digest: &Digest,
        reference: &Reference,
        actor: Option<&EventActor>,
    ) -> Self {
        Self::new(
            EventSubject::ManifestPush {
                digest: digest.clone(),
                reference: reference.clone(),
            },
            namespace.clone(),
            repository.to_string(),
            actor.cloned(),
        )
    }

    /// The `ManifestPush` event a put emits, a `TagCreate` when the reference
    /// is a tag, and one `TagCreate` per tag created via a `?tag=` query
    /// parameter.
    pub fn put_manifest(
        namespace: &Namespace,
        repository: &str,
        digest: &Digest,
        reference: &Reference,
        created_tags: &[Tag],
        actor: Option<&EventActor>,
    ) -> Vec<Self> {
        let mut events = vec![Self::push_manifest(
            namespace, repository, digest, reference, actor,
        )];
        events.extend(
            reference
                .as_tag()
                .into_iter()
                .chain(created_tags)
                .map(|tag| {
                    Self::new(
                        EventSubject::TagCreate {
                            digest: digest.clone(),
                            reference: reference.clone(),
                            tag: tag.clone(),
                        },
                        namespace.clone(),
                        repository.to_string(),
                        actor.cloned(),
                    )
                }),
        );
        events
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use angos_oci::{Digest, Namespace, Reference, Tag};

    use crate::{
        event_webhook::event::{Event, EventActor, EventKind, EventSubject},
        identity::ClientIdentity,
    };

    const FIXTURE_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

    /// The webhook body is a published contract: each kind must keep naming
    /// itself and its references with the keys subscribers already parse, and
    /// keep omitting the ones it does not carry.
    #[test]
    fn each_kind_keeps_its_published_payload_shape() {
        let digest: Digest = FIXTURE_DIGEST.parse().unwrap();
        let tag = Tag::new("latest").unwrap();
        let by_tag = Reference::Tag(tag.clone());
        let by_digest = Reference::Digest(digest.clone());

        let cases = [
            (
                EventSubject::ManifestPush {
                    digest: digest.clone(),
                    reference: by_tag.clone(),
                },
                json!({"kind": "manifest.push", "digest": FIXTURE_DIGEST, "reference": "latest"}),
            ),
            (
                EventSubject::ManifestPull {
                    digest: digest.clone(),
                    reference: by_tag.clone(),
                    tag: Some(tag.clone()),
                },
                json!({"kind": "manifest.pull", "digest": FIXTURE_DIGEST, "reference": "latest", "tag": "latest"}),
            ),
            (
                EventSubject::ManifestPull {
                    digest: digest.clone(),
                    reference: by_digest.clone(),
                    tag: None,
                },
                json!({"kind": "manifest.pull", "digest": FIXTURE_DIGEST, "reference": FIXTURE_DIGEST}),
            ),
            (
                EventSubject::ManifestDelete {
                    digest: None,
                    reference: by_tag.clone(),
                },
                json!({"kind": "manifest.delete", "reference": "latest"}),
            ),
            (
                EventSubject::ManifestDelete {
                    digest: Some(digest.clone()),
                    reference: by_digest,
                },
                json!({"kind": "manifest.delete", "digest": FIXTURE_DIGEST, "reference": FIXTURE_DIGEST}),
            ),
            (
                EventSubject::BlobPush {
                    digest: digest.clone(),
                },
                json!({"kind": "blob.push", "digest": FIXTURE_DIGEST}),
            ),
            (
                EventSubject::BlobPull {
                    digest: digest.clone(),
                },
                json!({"kind": "blob.pull", "digest": FIXTURE_DIGEST}),
            ),
            (
                EventSubject::TagCreate {
                    digest,
                    reference: by_tag.clone(),
                    tag: tag.clone(),
                },
                json!({"kind": "tag.create", "digest": FIXTURE_DIGEST, "reference": "latest", "tag": "latest"}),
            ),
            (
                EventSubject::TagDelete {
                    reference: by_tag,
                    tag,
                },
                json!({"kind": "tag.delete", "reference": "latest", "tag": "latest"}),
            ),
        ];

        for (subject, mut expected) in cases {
            let namespace = Namespace::new("library/nginx").unwrap();
            let event = Event::new(subject, namespace, "hub".to_string(), None);
            expected["namespace"] = json!("library/nginx");
            expected["repository"] = json!("hub");

            let mut body = serde_json::to_value(&event).unwrap();
            let fields = body.as_object_mut().unwrap();
            fields.remove("id");
            fields.remove("timestamp");
            assert_eq!(body, expected);
        }
    }

    /// One registry operation reports several events: a delete by tag also
    /// reports the tag, and a push reports one `tag.create` per tag it
    /// created. Only the by-digest forms name a digest.
    #[test]
    fn an_operation_reports_every_event_it_fans_out_to() {
        let namespace = Namespace::new("library/nginx").unwrap();
        let digest: Digest = FIXTURE_DIGEST.parse().unwrap();
        let tag = Tag::new("latest").unwrap();
        let by_tag = Reference::Tag(tag);
        let by_digest = Reference::Digest(digest.clone());
        let kinds = |events: &[Event]| -> Vec<&'static str> {
            events.iter().map(|event| event.kind().as_str()).collect()
        };
        let body = |event: &Event| serde_json::to_value(event).unwrap();

        let deleted_by_tag = Event::delete_manifest(&namespace, "hub", &by_tag, None);
        assert_eq!(
            kinds(&deleted_by_tag),
            vec!["manifest.delete", "tag.delete"]
        );
        assert!(body(&deleted_by_tag[0]).get("digest").is_none());
        assert_eq!(body(&deleted_by_tag[1])["tag"], json!("latest"));

        let deleted_by_digest = Event::delete_manifest(&namespace, "hub", &by_digest, None);
        assert_eq!(kinds(&deleted_by_digest), vec!["manifest.delete"]);
        assert_eq!(body(&deleted_by_digest[0])["digest"], json!(FIXTURE_DIGEST));

        let created = [Tag::new("stable").unwrap()];
        let pushed_by_tag =
            Event::put_manifest(&namespace, "hub", &digest, &by_tag, &created, None);
        assert_eq!(
            kinds(&pushed_by_tag),
            vec!["manifest.push", "tag.create", "tag.create"]
        );
        assert_eq!(body(&pushed_by_tag[1])["tag"], json!("latest"));
        assert_eq!(body(&pushed_by_tag[2])["tag"], json!("stable"));

        let pushed_by_digest =
            Event::put_manifest(&namespace, "hub", &digest, &by_digest, &[], None);
        assert_eq!(kinds(&pushed_by_digest), vec!["manifest.push"]);
    }
}
