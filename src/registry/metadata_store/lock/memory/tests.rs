use crate::registry::metadata_store::lock::{LockBackend, MemoryBackend};

#[tokio::test]
async fn test_acquire_lock() {
    let memory_backend = MemoryBackend::new();

    let lock = memory_backend.acquire("test").await.unwrap();
    assert_eq!(memory_backend.get_lock_count().await, 1);

    drop(lock);
    assert_eq!(memory_backend.get_lock_count().await, 0);
}
