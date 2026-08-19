use std::io::Cursor;

use chrono::{Duration, Utc};
use futures_util::TryStreamExt;
use tokio::io::AsyncReadExt;

use angos_oci::{Algorithm, Digest, Namespace, UploadSessionId};
use angos_storage::test_util::frame;

use crate::registry::Error;
use crate::registry::blob_store::resumable_hasher::Hasher;
use crate::registry::blob_store::*;

pub async fn test_datastore_stream_uploads(store: &BlobStore) {
    let namespace = &Namespace::new("test-repo").unwrap();

    let upload_ids: Vec<UploadSessionId> = (0..3).map(|_| UploadSessionId::generate()).collect();
    for id in &upload_ids {
        store.create_upload(namespace, id, None).await.unwrap();

        let content = format!("Content for upload {id}").into_bytes();
        let len = content.len() as u64;
        store
            .write_upload(
                namespace,
                id,
                Box::new(Cursor::new(content)),
                Some(len),
                Algorithm::Sha256,
            )
            .await
            .unwrap();
    }

    let uploads: Vec<UploadSessionId> =
        store.stream_uploads(namespace).try_collect().await.unwrap();
    assert_eq!(uploads.len(), upload_ids.len());
    for id in &upload_ids {
        assert!(uploads.contains(id));
    }

    let upload_to_complete = &upload_ids[0];
    let completed_digest =
        Digest::sha256_of_bytes(format!("Content for upload {upload_to_complete}").as_bytes());
    store
        .complete_upload(
            namespace,
            upload_to_complete,
            &completed_digest,
            format!("Content for upload {upload_to_complete}").len() as u64,
        )
        .await
        .unwrap();

    let uploads_after_complete: Vec<UploadSessionId> =
        store.stream_uploads(namespace).try_collect().await.unwrap();
    assert_eq!(uploads_after_complete.len(), upload_ids.len() - 1);
    assert!(!uploads_after_complete.contains(upload_to_complete));
}

/// Seed the backend with `content` at the canonical blob path for `algorithm`
/// by driving the upload workflow (`create_upload` → `write_upload` →
/// `complete_upload`). Mirrors how production creates blobs.
async fn seed_blob_with(store: &BlobStore, content: &[u8], algorithm: Algorithm) -> Digest {
    let namespace = Namespace::new("test/setup").unwrap();
    let session_id = UploadSessionId::generate();
    store
        .create_upload(&namespace, &session_id, None)
        .await
        .unwrap();
    let len = content.len() as u64;
    store
        .write_upload(
            &namespace,
            &session_id,
            Box::new(Cursor::new(content.to_vec())),
            Some(len),
            algorithm,
        )
        .await
        .unwrap();
    let expected = Digest::from_bytes(algorithm, content);
    store
        .complete_upload(&namespace, &session_id, &expected, len)
        .await
        .unwrap()
}

async fn seed_blob(store: &BlobStore, content: &[u8]) -> Digest {
    seed_blob_with(store, content, Algorithm::Sha256).await
}

pub async fn test_datastore_stream_blobs(store: &BlobStore) {
    let blob_contents = [
        b"aaa_content_1".to_vec(),
        b"bbb_content_2".to_vec(),
        b"ccc_content_3".to_vec(),
    ];

    let mut digests = Vec::new();
    for content in &blob_contents {
        digests.push(seed_blob(store, content).await);
    }

    let blobs: Vec<Digest> = store.stream_blobs().try_collect().await.unwrap();
    assert!(blobs.len() >= digests.len());
    for digest in &digests {
        assert!(blobs.contains(digest));
    }
}

pub async fn test_datastore_stream_blobs_across_algorithms(store: &BlobStore) {
    // Blobs of both algorithms live under separate prefixes; the stream must
    // walk across the boundary and surface each exactly once.
    let mut expected = Vec::new();
    for algorithm in [Algorithm::Sha256, Algorithm::Sha512] {
        for content in [b"alpha".as_slice(), b"beta".as_slice()] {
            expected.push(seed_blob_with(store, content, algorithm).await);
        }
    }

    let walked: Vec<Digest> = store.stream_blobs().try_collect().await.unwrap();
    assert_eq!(walked.len(), expected.len());
    for digest in &expected {
        assert!(walked.contains(digest), "missed {digest}");
    }
}

pub async fn test_datastore_blob_operations(store: &BlobStore) {
    let test_content = b"Test blob content";
    let digest = seed_blob(store, test_content).await;

    let retrieved_content = store.read(&digest).await.unwrap();
    assert_eq!(retrieved_content, test_content);

    let size = store.size(&digest).await.unwrap();
    assert_eq!(size, test_content.len() as u64);

    let (mut reader, _) = store.reader(&digest, None).await.unwrap();
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).await.unwrap();
    assert_eq!(buffer, test_content);
}

pub async fn test_build_blob_reader_returns_size(store: &BlobStore) {
    let test_content = b"blob reader size test content";
    let digest = seed_blob(store, test_content).await;

    let (mut reader, size) = store.reader(&digest, None).await.unwrap();
    assert_eq!(size, test_content.len() as u64);

    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).await.unwrap();
    assert_eq!(buffer, test_content);
}

#[allow(clippy::cast_possible_truncation)]
pub async fn test_build_blob_reader_with_offset_returns_full_size(store: &BlobStore) {
    let test_content = b"offset blob reader content here";
    let digest = seed_blob(store, test_content).await;
    let offset = 10u64;

    let (mut reader, size) = store.reader(&digest, Some(offset)).await.unwrap();
    assert_eq!(size, test_content.len() as u64);

    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).await.unwrap();
    assert_eq!(buffer, &test_content[offset as usize..]);
}

pub async fn test_datastore_upload_operations(store: &BlobStore) {
    let namespace = &Namespace::new("test-namespace").unwrap();
    let session_id = UploadSessionId::generate();

    store
        .create_upload(namespace, &session_id, None)
        .await
        .unwrap();

    let test_content = b"Test upload content";

    let expected_digest = Digest::sha256_of_bytes(test_content);

    store
        .write_upload(
            namespace,
            &session_id,
            Box::new(Cursor::new(test_content.to_vec())),
            Some(test_content.len() as u64),
            Algorithm::Sha256,
        )
        .await
        .unwrap();

    let summary = store.upload_summary(namespace, &session_id).await.unwrap();
    assert_eq!(summary.size, test_content.len() as u64);
    assert!(Utc::now().signed_duration_since(summary.started_at) < Duration::hours(1));

    let final_digest = store
        .complete_upload(
            namespace,
            &session_id,
            &expected_digest,
            test_content.len() as u64,
        )
        .await
        .unwrap();
    assert_eq!(final_digest, expected_digest);

    let blob_content = store.read(&final_digest).await.unwrap();
    assert_eq!(blob_content, test_content);

    let upload_result = store.upload_summary(namespace, &session_id).await;
    assert!(upload_result.is_err());
}

/// Repeated promotion of identical content converges on one blob. Two
/// independent uploads of the same bytes both complete: the second moves onto
/// the already-present content-addressed path (overwriting identical bytes),
/// yields the same digest with intact content, and both sessions are swept.
/// Covers promotion onto an existing destination plus best-effort session
/// cleanup; single-session crash re-drive is the caller's `size(digest)` gate.
pub async fn test_repeated_promotion_converges(store: &BlobStore) {
    let content = b"idempotent promotion content";
    let first = seed_blob(store, content).await;
    let second = seed_blob(store, content).await;

    assert_eq!(first, second, "identical content must map to one blob");
    assert_eq!(store.read(&first).await.unwrap(), content);

    let namespace = Namespace::new("test/setup").unwrap();
    let uploads: Vec<UploadSessionId> = store
        .stream_uploads(&namespace)
        .try_collect()
        .await
        .unwrap();
    assert!(
        uploads.is_empty(),
        "promoted sessions must be swept: {uploads:?}"
    );
}

/// `complete_upload` consumes the session's liveness marker, so a second call on
/// the same session returns `UploadNotFound` and leaves the promoted blob
/// intact. A naive S3 re-finalize would overwrite the blob with an empty object,
/// so this guards that the marker is consumed before the multipart-complete.
pub async fn test_complete_upload_fails_on_rerun(store: &BlobStore) {
    let namespace = Namespace::new("test/rerun").unwrap();
    let session_id = UploadSessionId::generate();
    let content = b"one-shot completion";
    store
        .create_upload(&namespace, &session_id, None)
        .await
        .unwrap();
    store
        .write_upload(
            &namespace,
            &session_id,
            Box::new(Cursor::new(content.to_vec())),
            Some(content.len() as u64),
            Algorithm::Sha256,
        )
        .await
        .unwrap();
    let digest = Digest::sha256_of_bytes(content);
    store
        .complete_upload(&namespace, &session_id, &digest, content.len() as u64)
        .await
        .unwrap();

    let rerun = store
        .complete_upload(&namespace, &session_id, &digest, content.len() as u64)
        .await;
    assert!(
        matches!(rerun, Err(Error::BlobUploadUnknown)),
        "re-run of a completed session must fail: {rerun:?}"
    );
    assert_eq!(
        store.read(&digest).await.unwrap(),
        content,
        "blob must stay intact after a rejected re-run"
    );
}

/// A directory naming no session is scrub's to quarantine, so the sweep that
/// reaps live sessions must not report it as one.
pub async fn test_datastore_stream_uploads_skips_a_non_session_name(store: &BlobStore) {
    let namespace = &Namespace::new("test-raw-upload").unwrap();
    let session = UploadSessionId::generate();
    store
        .create_upload(namespace, &session, None)
        .await
        .unwrap();

    let stray = "v2/repositories/test-raw-upload/_uploads/not-a-session/startedat";
    store
        .object_store()
        .put(stray, Bytes::from_static(b"2026-01-01T00:00:00Z"))
        .await
        .unwrap();

    let uploads: Vec<UploadSessionId> =
        store.stream_uploads(namespace).try_collect().await.unwrap();
    assert_eq!(
        uploads,
        vec![session],
        "only the opened session may be reported"
    );
}

// Test entry points: run each helper against every backend fixture

use crate::registry::test_utils::{FSRegistryTestCase, RegistryTestCase, for_each_backend};

#[tokio::test]
async fn stream_uploads() {
    for_each_backend(async |tc| {
        test_datastore_stream_uploads(tc.blob_store().as_ref()).await;
    })
    .await;
}

#[tokio::test]
async fn stream_uploads_skips_a_non_session_name() {
    for_each_backend(async |tc| {
        test_datastore_stream_uploads_skips_a_non_session_name(tc.blob_store().as_ref()).await;
    })
    .await;
}

#[tokio::test]
async fn stream_blobs() {
    for_each_backend(async |tc| {
        test_datastore_stream_blobs(tc.blob_store().as_ref()).await;
    })
    .await;
}

#[tokio::test]
async fn stream_blobs_across_algorithms() {
    for_each_backend(async |tc| {
        test_datastore_stream_blobs_across_algorithms(tc.blob_store().as_ref()).await;
    })
    .await;
}

#[tokio::test]
async fn blob_operations() {
    for_each_backend(async |tc| {
        test_datastore_blob_operations(tc.blob_store().as_ref()).await;
    })
    .await;
}

#[tokio::test]
async fn blob_reader_returns_size() {
    for_each_backend(async |tc| {
        test_build_blob_reader_returns_size(tc.blob_store().as_ref()).await;
    })
    .await;
}

#[tokio::test]
async fn blob_reader_with_offset_returns_full_size() {
    for_each_backend(async |tc| {
        test_build_blob_reader_with_offset_returns_full_size(tc.blob_store().as_ref()).await;
    })
    .await;
}

#[tokio::test]
async fn upload_operations() {
    for_each_backend(async |tc| {
        test_datastore_upload_operations(tc.blob_store().as_ref()).await;
    })
    .await;
}

#[tokio::test]
async fn repeated_promotion_converges() {
    for_each_backend(async |tc| {
        test_repeated_promotion_converges(tc.blob_store().as_ref()).await;
    })
    .await;
}

#[tokio::test]
async fn complete_upload_fails_on_rerun() {
    for_each_backend(async |tc| {
        test_complete_upload_fails_on_rerun(tc.blob_store().as_ref()).await;
    })
    .await;
}

/// FS-only: the assertions are about the exact keys under one prefix, which
/// the shared backends agree on, and this keeps the check independent of a
/// live S3.
#[tokio::test]
async fn session_state_is_one_json_record() {
    let tc = FSRegistryTestCase::new();
    test_session_state_is_one_json_record(tc.blob_store().as_ref()).await;
}

/// FS-only: the legacy artifacts are seeded raw, and only the FS backend
/// accepts appends to a data file it did not open through `create_upload`'s
/// multipart machinery.
#[tokio::test]
async fn legacy_session_resumes_and_completes() {
    let tc = FSRegistryTestCase::new();
    test_legacy_session_resumes_and_completes(tc.blob_store().as_ref()).await;
}

#[tokio::test]
async fn complete_upload_rejects_size_divergence() {
    for_each_backend(async |tc| {
        test_complete_upload_rejects_size_divergence(tc.blob_store().as_ref()).await;
    })
    .await;
}

/// An append that fails after durably writing bytes leaves the staging object
/// longer than the checkpoint records, and the resume that follows hashes only
/// its own bytes, so the digest matches while the stored bytes do not. The
/// orphaned tail is written directly here because no backend error is needed to
/// reach the state, only the size divergence it leaves behind.
pub async fn test_complete_upload_rejects_size_divergence(store: &BlobStore) {
    let tail = b"orphaned tail".to_vec();
    let namespace = Namespace::new("test/divergence").unwrap();
    let session_id = UploadSessionId::generate();
    let content = b"hashed prefix";
    store
        .create_upload(&namespace, &session_id, None)
        .await
        .unwrap();
    store
        .write_upload(
            &namespace,
            &session_id,
            Box::new(Cursor::new(content.to_vec())),
            Some(content.len() as u64),
            Algorithm::Sha256,
        )
        .await
        .unwrap();

    // Bytes the session hashed, then a tail it never did.
    let upload_key = path_builder::upload_path(&namespace, &session_id);
    store
        .object
        .write_upload(&upload_key, frame(tail.clone()), Some(tail.len() as u64))
        .await
        .unwrap();

    let digest = Digest::sha256_of_bytes(content);
    let result = store
        .complete_upload(&namespace, &session_id, &digest, content.len() as u64)
        .await;

    assert!(
        matches!(result, Err(Error::DigestInvalid)),
        "a staged object longer than the hashed size must not be promoted: {result:?}"
    );
    assert!(
        matches!(store.read(&digest).await, Err(Error::BlobUnknown)),
        "the diverged bytes must never reach the canonical blob path"
    );
}

/// A chunked upload keeps its whole state in one `session.json`, rewritten
/// per chunk: no `hashstates/` or `startedat` keys appear, the checkpoint
/// resumes across chunks, and completion leaves no session keys behind.
pub async fn test_session_state_is_one_json_record(store: &BlobStore) {
    let namespace = &Namespace::new("session-single-record").unwrap();
    let session_id = &UploadSessionId::generate();
    store
        .create_upload(namespace, session_id, None)
        .await
        .unwrap();

    for chunk in ["one", "two", "three", "four"] {
        store
            .write_upload(
                namespace,
                session_id,
                Box::new(Cursor::new(chunk.as_bytes().to_vec())),
                Some(chunk.len() as u64),
                Algorithm::Sha256,
            )
            .await
            .unwrap();
    }

    let container = format!(
        "{}/",
        path_builder::upload_container_path(namespace, session_id)
    );
    let keys = store
        .object
        .list(&container, 100, None)
        .await
        .unwrap()
        .items;
    assert_eq!(
        keys.iter().filter(|k| k.contains("session.json")).count(),
        1,
        "exactly one session record expected, got: {keys:?}"
    );
    assert!(
        !keys
            .iter()
            .any(|k| k.contains("hashstates") || k.contains("startedat")),
        "no legacy artifacts may be written: {keys:?}"
    );

    // The checkpoint resumed across chunks iff the digest of the whole body
    // verifies at completion.
    let content = b"onetwothreefour";
    let digest = Digest::sha256_of_bytes(content);
    store
        .complete_upload(namespace, session_id, &digest, content.len() as u64)
        .await
        .unwrap();
    assert_eq!(store.read(&digest).await.unwrap(), content);
    let leftover = store
        .object
        .list(&container, 100, None)
        .await
        .unwrap()
        .items;
    assert!(
        leftover.is_empty(),
        "completion must leave no session keys: {leftover:?}"
    );
}

/// A session persisted by a previous binary (raw `startedat` marker, a
/// `hashstates/<offset>` checkpoint, and partial data) resumes under the new
/// code, which writes `session.json` on the first activity, and completes.
pub async fn test_legacy_session_resumes_and_completes(store: &BlobStore) {
    let namespace = &Namespace::new("legacy-session").unwrap();
    let session_id = &UploadSessionId::generate();
    let first = b"first half ";
    let rest = b"second half";

    let upload_path = path_builder::upload_path(namespace, session_id);
    store.object.create_upload(&upload_path).await.unwrap();
    store
        .object
        .write_upload(
            &upload_path,
            frame(first.to_vec()),
            Some(first.len() as u64),
        )
        .await
        .unwrap();
    let mut hasher = Hasher::new();
    hasher.update(first);
    store
        .object
        .put(
            &path_builder::upload_hash_context_path(namespace, session_id, first.len() as u64),
            Bytes::from(hasher.state().to_bytes().unwrap()),
        )
        .await
        .unwrap();
    store
        .object
        .put(
            &path_builder::upload_start_date_path(namespace, session_id),
            Bytes::from(Utc::now().to_rfc3339()),
        )
        .await
        .unwrap();

    let (digest, size) = store
        .write_upload(
            namespace,
            session_id,
            Box::new(Cursor::new(rest.to_vec())),
            Some(rest.len() as u64),
            Algorithm::Sha256,
        )
        .await
        .unwrap();
    let content = b"first half second half";
    assert_eq!(size, content.len() as u64);
    assert_eq!(digest, Digest::sha256_of_bytes(content));
    assert!(
        store
            .object
            .head(&path_builder::upload_session_path(namespace, session_id))
            .await
            .is_ok(),
        "the first activity on a legacy session must write session.json"
    );

    store
        .complete_upload(namespace, session_id, &digest, size)
        .await
        .unwrap();
    assert_eq!(store.read(&digest).await.unwrap(), content);
    let container = format!(
        "{}/",
        path_builder::upload_container_path(namespace, session_id)
    );
    let leftover = store
        .object
        .list(&container, 100, None)
        .await
        .unwrap()
        .items;
    assert!(
        leftover.is_empty(),
        "completion must sweep the legacy artifacts too: {leftover:?}"
    );
}
