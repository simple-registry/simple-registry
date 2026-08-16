//! On-disk shape of a transaction intent record.
//!
//! An intent record is written to `.tx-log/<tx-id>.json` before any canonical
//! keys are mutated. It is the linearisation point: once this write succeeds,
//! the transaction WILL be observed (either by the owning worker finishing
//! Apply/Reap, or by the recovery loop replaying it).
//!
//! A `Put` or `PutIfAbsent` body up to [`INLINE_BODY_MAX_BYTES`] travels in the
//! record itself, which spares the staging write and the read that would fetch
//! it back. A larger one is staged at `.tx-bodies/<tx-id>/<idx>` *before* the
//! intent PUT, so the intent JSON stays small; its `body` field then records
//! where to find the bytes during Apply and recovery.

/// Default intent TTL in seconds used by both executors when no explicit TTL
/// is provided. Named here so the value is defined once and referenced by both
/// `CasExecutor` and `LockedExecutor` builders.
pub const DEFAULT_INTENT_TTL_SECS: u64 = 300;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;
use uuid::Uuid;

use angos_storage::Etag;

use crate::transaction::Read;

/// Largest body carried inside an intent record rather than staged under
/// `.tx-bodies/`.
///
/// Either route moves the bytes twice (inline, because the record is written to
/// log the transaction and again to stamp its commit point; staged, because the
/// body is written then read back), so the cap is not about bandwidth. It bounds
/// the record instead: the intent PUT is a serialisation point that Apply waits
/// on, while staging writes run concurrently, and every sweep of the recovery
/// loop and the body janitor re-reads each record. At this cap a full
/// transaction's bodies stay near a megabyte encoded, which is under what one
/// round trip is worth, and a link body runs about a kilobyte.
pub const INLINE_BODY_MAX_BYTES: usize = 64 * 1024;

/// Where a `Put`/`PutIfAbsent` mutation's bytes live.
///
/// The staged spelling is a bare string, the one the intent log has always
/// used, so a record any earlier angos wrote still replays.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum MutationBody {
    /// Bytes staged at `.tx-bodies/<tx-id>/<idx>`.
    Staged(String),
    /// Bytes carried in the record, base64 so arbitrary content survives JSON.
    Inline {
        #[serde(rename = "inline", with = "inline_body")]
        bytes: Bytes,
    },
}

/// Base64 codec for an inline body, so a body that is not valid UTF-8 still
/// round-trips through the JSON record.
mod inline_body {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Bytes, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(&encoded)
            .map(Bytes::from)
            .map_err(D::Error::custom)
    }
}

/// The operation variant recorded in an intent record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op")]
pub enum MutationRecord {
    /// Write `body` to `key`.
    ///
    /// `expected` is honored by both executors: the CAS executor via
    /// `put_if_match`, and the Locked executor via a HEAD + `ETag` comparison
    /// under the lock.
    Put {
        key: String,
        /// The wire name is the one the intent log has always used.
        #[serde(rename = "body_ref")]
        body: MutationBody,
        expected: Option<Etag>,
    },
    /// Write `body` to `key` only if the key is absent.
    PutIfAbsent {
        key: String,
        #[serde(rename = "body_ref")]
        body: MutationBody,
    },
    /// Delete `key`.
    ///
    /// `expected` is honored by both executors: the CAS executor via
    /// `delete_if_match`, and the Locked executor via a HEAD + `ETag` comparison
    /// under the lock.
    Delete { key: String, expected: Option<Etag> },
    /// Idempotently merge `add`/`remove` into the JSON-array set at `key`.
    ///
    /// Carries no body (the small deltas live inline) and no etag: each
    /// apply and replay re-reads live state and recomputes, so it always
    /// converges instead of leaving a permanent partial commit.
    MergeSet {
        key: String,
        add: Vec<Value>,
        remove: Vec<Value>,
    },
}

impl MutationRecord {
    /// Return the canonical key this mutation touches. Used by recovery to
    /// reconstruct the transaction's lock set without rebuilding the original
    /// `Transaction` value.
    pub fn key(&self) -> &str {
        match self {
            MutationRecord::Put { key, .. }
            | MutationRecord::PutIfAbsent { key, .. }
            | MutationRecord::Delete { key, .. }
            | MutationRecord::MergeSet { key, .. } => key,
        }
    }
}

/// Per-mutation apply progress recorded in the intent log.
///
/// Carried by the [`PlannedMutation`] it belongs to. `Pending`
/// means the mutation has not yet been confirmed applied; `Applied` means
/// the engine observed a successful apply. Only the discriminant matters:
/// recovery and `any_applied` inspect `Applied` to decide replay-forward vs
/// rollback and to skip already-applied slots, but the value carries no
/// payload.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum MutationProgress {
    Pending,
    Applied,
}

/// Staging key for the body of mutation `idx` in transaction `id`.
///
/// Prefix of the intent log: one `<tx-id>.json` record per in-flight
/// transaction. Engine-owned; external maintenance must never touch it.
pub const INTENT_LOG_PREFIX: &str = ".tx-log";

/// Prefix of the staged mutation bodies, one `<tx-id>/<idx>` object per
/// mutation. Engine-owned; the `BodyJanitor` reclaims orphans.
pub const INTENT_BODIES_PREFIX: &str = ".tx-bodies";

/// Single source of truth for the `.tx-bodies/<tx-id>/<idx>` shape, shared by
/// [`IntentRecord::body_ref`] and the body-staging path in the executors.
#[must_use]
pub fn body_ref_key(id: Uuid, idx: usize) -> String {
    format!("{INTENT_BODIES_PREFIX}/{id}/{idx}")
}

/// One mutation of an intent together with how far it has been applied.
/// Recovery reasons about the pair, so they travel as one value instead of two
/// arrays whose lengths could only ever agree by convention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedMutation {
    pub record: MutationRecord,
    pub progress: MutationProgress,
}

/// The complete intent record written to `.tx-log/<tx-id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "StoredIntent")]
pub struct IntentRecord {
    /// Unique transaction identifier.
    pub id: Uuid,
    /// Wall-clock time at which the intent was written.
    pub created_at: DateTime<Utc>,
    /// Seconds after `created_at` at which the intent is considered stale
    /// by the recovery loop.
    pub ttl_secs: u64,
    /// Read dependencies.
    pub reads: Vec<Read>,
    /// Ordered mutations, each carrying its own apply progress. Initialised to
    /// `Pending` when the intent is first written and stamped to `Applied`
    /// after each successful apply; recovery reads them to decide
    /// replay-forward vs rollback (any `Applied` entry implies the transaction
    /// is committed).
    pub mutations: Vec<PlannedMutation>,
}

/// A mutation as a stored intent may hold it: paired with its own progress,
/// or bare beside a top-level `progress` array, which is how every angos before
/// the pairing wrote it.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredMutation {
    Paired(PlannedMutation),
    Bare(MutationRecord),
}

/// The read side of `.tx-log/`, accepting both shapes so a record written
/// before the pairing still replays. Writing goes through the derive on
/// [`IntentRecord`], so new records carry the paired shape.
///
/// TODO: drop this type in a future minor release
#[derive(Deserialize)]
struct StoredIntent {
    id: Uuid,
    created_at: DateTime<Utc>,
    ttl_secs: u64,
    reads: Vec<Read>,
    mutations: Vec<StoredMutation>,
    #[serde(default)]
    progress: Option<Vec<MutationProgress>>,
}

impl TryFrom<StoredIntent> for IntentRecord {
    type Error = String;

    fn try_from(stored: StoredIntent) -> Result<Self, Self::Error> {
        let id = stored.id;
        // A bare mutation draws its progress from the companion array, in order.
        // Running out either way means the record cannot be replayed faithfully,
        // so it is refused rather than padded or truncated.
        let mut legacy_progress = stored.progress.unwrap_or_default().into_iter();
        let mutations = stored
            .mutations
            .into_iter()
            .map(|stored| match stored {
                StoredMutation::Paired(planned) => Ok(planned),
                StoredMutation::Bare(record) => legacy_progress
                    .next()
                    .map(|progress| PlannedMutation { record, progress })
                    .ok_or_else(|| format!("intent {id} has more mutations than progress slots")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if legacy_progress.next().is_some() {
            return Err(format!(
                "intent {id} has more progress slots than mutations"
            ));
        }

        Ok(Self {
            id,
            created_at: stored.created_at,
            ttl_secs: stored.ttl_secs,
            reads: stored.reads,
            mutations,
        })
    }
}

impl IntentRecord {
    /// Return the object key under which this intent is stored.
    #[must_use]
    pub fn log_key(&self) -> String {
        format!("{INTENT_LOG_PREFIX}/{}.json", self.id)
    }

    /// Return the `.tx-bodies` prefix for mutation body staging.
    #[must_use]
    pub fn bodies_prefix(&self) -> String {
        format!("{INTENT_BODIES_PREFIX}/{}/", self.id)
    }

    /// Return the staging key for mutation body at index `idx`.
    #[must_use]
    pub fn body_ref(&self, idx: usize) -> String {
        body_ref_key(self.id, idx)
    }

    /// Whether any mutation staged its body under `.tx-bodies/`. A transaction
    /// whose bodies all rode inline has no staging prefix to reclaim.
    #[must_use]
    pub fn has_staged_bodies(&self) -> bool {
        self.mutations.iter().any(|planned| {
            matches!(
                &planned.record,
                MutationRecord::Put {
                    body: MutationBody::Staged(_),
                    ..
                } | MutationRecord::PutIfAbsent {
                    body: MutationBody::Staged(_),
                    ..
                }
            )
        })
    }

    /// Returns `true` if the owner's heartbeat is considered stale.
    #[must_use]
    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        let expiry = self.created_at + Duration::seconds(self.ttl_secs.cast_signed());
        now > expiry
    }

    /// Returns `true` if at least one mutation in this transaction has been
    /// applied (derived from `progress`).
    #[must_use]
    pub fn any_applied(&self) -> bool {
        self.mutations
            .iter()
            .any(|planned| matches!(planned.progress, MutationProgress::Applied))
    }

    /// How far mutation `idx` has been applied, or `None` past the end.
    #[must_use]
    pub fn progress(&self, idx: usize) -> Option<MutationProgress> {
        self.mutations.get(idx).map(|planned| planned.progress)
    }

    /// Record that mutation `idx` has been applied. A no-op (with a warning)
    /// when `idx` is out of range, defending against a malformed intent without
    /// panicking.
    pub fn mark_applied(&mut self, idx: usize) {
        let Some(planned) = self.mutations.get_mut(idx) else {
            warn!(
                tx_id = %self.id,
                idx,
                len = self.mutations.len(),
                "mark_applied called with out-of-range index; ignoring"
            );
            return;
        };
        planned.progress = MutationProgress::Applied;
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use chrono::Utc;
    use uuid::Uuid;

    use crate::intent::{
        IntentRecord, MutationBody, MutationProgress, MutationRecord, PlannedMutation,
    };
    use crate::transaction::{Expectation, Fingerprint, Read};

    fn sample_intent(progress: Vec<MutationProgress>) -> IntentRecord {
        let mutations = progress
            .into_iter()
            .enumerate()
            .map(|(idx, progress)| PlannedMutation {
                record: MutationRecord::Put {
                    key: format!("k{idx}"),
                    body: MutationBody::Staged(format!("b{idx}")),
                    expected: None,
                },
                progress,
            })
            .collect();
        IntentRecord {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            ttl_secs: 300,
            reads: vec![],
            mutations,
        }
    }

    /// The intent log is durable, so a read's spelling is a stored format: hex
    /// digits for an observed body, empty for an absent key, under the
    /// `fingerprint` name. Both directions, so an intent any earlier angos
    /// wrote still replays and one this build writes is still readable by a
    /// peer running that build.
    #[test]
    fn a_stored_read_keeps_its_spelling() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let mut fingerprint: Fingerprint = [0; 32];
        hex::decode_to_slice(hex, &mut fingerprint).unwrap();

        let cases = [
            (
                Read {
                    key: "k".to_string(),
                    expected: Expectation::Present(fingerprint),
                },
                format!(r#"{{"key":"k","fingerprint":"{hex}"}}"#),
            ),
            (
                Read {
                    key: "k".to_string(),
                    expected: Expectation::Absent,
                },
                r#"{"key":"k","fingerprint":""}"#.to_string(),
            ),
        ];

        for (read, stored) in cases {
            assert_eq!(
                serde_json::to_string(&read).unwrap(),
                stored,
                "the read must keep the spelling the intent log already holds"
            );
            assert_eq!(
                serde_json::from_str::<Read>(&stored).unwrap(),
                read,
                "a stored read must read back unchanged"
            );
        }
    }

    /// A fingerprint that is not 32 bytes of hex cannot have been written by any
    /// angos, so refusing it keeps a corrupt record from replaying as a read the
    /// executor would silently accept.
    #[test]
    fn a_malformed_stored_read_is_refused() {
        for stored in [
            r#"{"key":"k","fingerprint":"nothex"}"#,
            r#"{"key":"k","fingerprint":"aabb"}"#,
        ] {
            assert!(
                serde_json::from_str::<Read>(stored).is_err(),
                "a malformed fingerprint must not parse: {stored}"
            );
        }
    }

    /// A staged body keeps the bare-string spelling every earlier angos wrote,
    /// so a new record is still the one an old one would recognise, and an
    /// inline body survives bytes that are not valid UTF-8.
    #[test]
    fn a_body_keeps_its_spelling_whichever_route_it_took() {
        let staged = MutationRecord::Put {
            key: "k".to_string(),
            body: MutationBody::Staged(".tx-bodies/x/0".to_string()),
            expected: None,
        };
        assert_eq!(
            serde_json::to_string(&staged).unwrap(),
            r#"{"op":"Put","key":"k","body_ref":".tx-bodies/x/0","expected":null}"#,
            "a staged body must stay a bare string under the name the log has always used"
        );

        let inline = MutationRecord::Put {
            key: "k".to_string(),
            body: MutationBody::Inline {
                bytes: Bytes::from_static(&[0xff, 0x00, 0xfe]),
            },
            expected: None,
        };
        let json = serde_json::to_string(&inline).unwrap();
        assert!(
            json.contains(r#""body_ref":{"inline":"/wD+"}"#),
            "an inline body must be base64 under the same name: {json}"
        );

        for record in [staged, inline] {
            assert_eq!(
                serde_json::from_str::<MutationRecord>(&serde_json::to_string(&record).unwrap())
                    .unwrap(),
                record,
                "a record must read back unchanged"
            );
        }
    }

    /// A whole `.tx-log/<id>.json` body as an earlier angos wrote it, so the
    /// record recovery replays from is checked end to end and not just the read
    /// entry in isolation.
    #[test]
    fn a_stored_intent_record_still_replays() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let stored = format!(
            r#"{{"id":"cfa8d910-641e-478a-8bd1-5718ac886223",
                 "created_at":"2026-08-04T19:38:52.196719Z","ttl_secs":300,
                 "reads":[{{"key":"present","fingerprint":"{hex}"}},
                          {{"key":"absent","fingerprint":""}}],
                 "mutations":[{{"op":"Put","key":"k0","body_ref":"b0","expected":null}}],
                 "coarse_lock_keys":[],"progress":["Pending"]}}"#
        );

        let intent: IntentRecord =
            serde_json::from_str(&stored).expect("a stored intent must still deserialize");

        let mut fingerprint: Fingerprint = [0; 32];
        hex::decode_to_slice(hex, &mut fingerprint).unwrap();
        assert_eq!(
            intent.reads,
            vec![
                Read {
                    key: "present".to_string(),
                    expected: Expectation::Present(fingerprint),
                },
                Read {
                    key: "absent".to_string(),
                    expected: Expectation::Absent,
                },
            ],
            "both read spellings must survive the round trip"
        );
        assert_eq!(intent.ttl_secs, 300);
        assert_eq!(intent.progress(0), Some(MutationProgress::Pending));
    }

    /// What this build writes is the paired shape, one array of mutations each
    /// carrying its own progress and no companion array.
    #[test]
    fn a_written_record_carries_the_paired_shape() {
        let intent = sample_intent(vec![MutationProgress::Applied, MutationProgress::Pending]);
        let json = serde_json::to_value(&intent).unwrap();

        assert!(
            !json.as_object().is_some_and(|o| o.contains_key("progress")),
            "the companion progress array must be gone: {json}"
        );
        assert_eq!(
            json["mutations"][0]["progress"], "Applied",
            "each mutation carries its own progress: {json}"
        );
        assert!(
            json["mutations"][0]["record"]["op"].is_string(),
            "the mutation itself sits under `record`: {json}"
        );

        let parsed: IntentRecord = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.mutations, intent.mutations);
    }

    /// A record written before the pairing keeps replaying: its bare mutations
    /// draw progress from the companion array, in order.
    #[test]
    fn a_two_array_record_still_replays() {
        let stored = serde_json::json!({
            "id": Uuid::new_v4(),
            "created_at": Utc::now(),
            "ttl_secs": 300,
            "reads": [],
            "mutations": [
                {"op": "Delete", "key": "k0", "expected": null},
                {"op": "Delete", "key": "k1", "expected": null},
            ],
            "coarse_lock_keys": [],
            "progress": ["Applied", "Pending"],
        });

        let intent: IntentRecord =
            serde_json::from_value(stored).expect("a two-array record must still parse");
        assert_eq!(intent.progress(0), Some(MutationProgress::Applied));
        assert_eq!(intent.progress(1), Some(MutationProgress::Pending));
        assert!(
            matches!(&intent.mutations[1].record, MutationRecord::Delete { key, .. } if key == "k1"),
            "the mutations must keep their order alongside their progress"
        );
    }

    /// A two-array record whose arrays disagree cannot be replayed faithfully:
    /// pairing would silently drop or invent a slot.
    #[test]
    fn a_desynced_stored_record_is_refused() {
        let stored = serde_json::json!({
            "id": Uuid::new_v4(),
            "created_at": Utc::now(),
            "ttl_secs": 300,
            "reads": [],
            "mutations": [
                {"op": "Delete", "key": "k0", "expected": null},
                {"op": "Delete", "key": "k1", "expected": null},
            ],
            "coarse_lock_keys": [],
            "progress": ["Pending"],
        });

        let error = serde_json::from_value::<IntentRecord>(stored)
            .expect_err("two mutations against one progress slot must not parse");
        assert!(
            error.to_string().contains("progress slots"),
            "the error must name the disagreement, got: {error}"
        );
    }

    #[test]
    fn progress_round_trips_through_serde() {
        let intent = sample_intent(vec![
            MutationProgress::Pending,
            MutationProgress::Applied,
            MutationProgress::Applied,
        ]);
        let json = serde_json::to_vec(&intent).expect("serialise");
        let back: IntentRecord = serde_json::from_slice(&json).expect("deserialise");
        assert_eq!(back.mutations, intent.mutations);
    }

    #[test]
    fn mark_applied_sets_correct_slot() {
        let mut intent = sample_intent(vec![MutationProgress::Pending; 3]);
        intent.mark_applied(1);
        assert_eq!(intent.mutations[0].progress, MutationProgress::Pending);
        assert_eq!(intent.mutations[1].progress, MutationProgress::Applied);
        assert_eq!(intent.mutations[2].progress, MutationProgress::Pending);
    }

    #[test]
    fn mark_applied_out_of_range_is_a_no_op() {
        let mut intent = sample_intent(vec![MutationProgress::Pending; 2]);
        intent.mark_applied(5);
        assert!(
            intent
                .mutations
                .iter()
                .all(|planned| matches!(planned.progress, MutationProgress::Pending))
        );
    }

    #[test]
    fn any_applied_reflects_progress() {
        let intent = sample_intent(vec![MutationProgress::Pending; 3]);
        assert!(!intent.any_applied());

        let intent = sample_intent(vec![
            MutationProgress::Pending,
            MutationProgress::Applied,
            MutationProgress::Pending,
        ]);
        assert!(intent.any_applied());
    }
}
