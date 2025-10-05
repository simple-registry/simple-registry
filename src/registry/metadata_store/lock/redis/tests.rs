use crate::registry::metadata_store::lock::redis::LockConfig;
use crate::registry::metadata_store::lock::{LockBackend, RedisBackend};

#[tokio::test]
async fn test_acquire_lock() {
    let config = LockConfig {
        url: "redis://localhost:6379/2".to_owned(),
        ttl: 2,
        key_prefix: "test_acquire_lock_".to_owned(),
        max_retries: 0, // No retries for this test
        retry_delay_ms: 5,
    };

    let redis_backend = RedisBackend::new(&config).expect("Failed to create RedisBackend");
    let redis_backend2 = RedisBackend::new(&config).expect("Failed to create RedisBackend");

    // Step 1: Acquire the lock
    let lock = redis_backend
        .acquire("test_key")
        .await
        .expect("Failed to acquire initial lock");

    // Step 2: Check the lock exists (another instance can't acquire it)
    let lock_attempt = redis_backend2.acquire("test_key").await;
    assert!(
        lock_attempt.is_err(),
        "Should not be able to acquire an already held lock"
    );

    // Step 3: Drop the lock to release it
    drop(lock);

    // Step 4: Check the lock doesn't exist anymore (can acquire it again)
    let new_lock = redis_backend
        .acquire("test_key")
        .await
        .expect("Should be able to acquire lock after it was released");

    // Clean up
    drop(new_lock);
}
