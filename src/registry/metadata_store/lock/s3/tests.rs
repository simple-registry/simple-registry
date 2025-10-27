use crate::registry::metadata_store::lock::s3::LockConfig;
use crate::registry::metadata_store::lock::{LockBackend, S3Backend};
use uuid::Uuid;

#[tokio::test]
async fn test_acquire_lock() {
    let config = LockConfig {
        access_key_id: "root".to_string(),
        secret_key: "roottoor".to_string(),
        endpoint: "http://localhost:9000".to_string(),
        bucket: "registry".to_string(),
        region: "us-east-1".to_string(),
        key_prefix: format!("test/{}", Uuid::new_v4()),
        ttl: 2,
        max_retries: 10,
        retry_delay_ms: 10,
    };

    let backend = S3Backend::new(&config).expect("Failed to create S3Backend");
    let backend2 = S3Backend::new(&config).expect("Failed to create S3Backend");

    // Step 1: Acquire the lock
    let lock = backend
        .acquire("test_key")
        .await
        .expect("Failed to acquire initial lock");

    // Step 2: Check the lock exists (another instance can't acquire it)
    let lock_attempt = backend2.acquire("test_key").await;
    assert!(
        lock_attempt.is_err(),
        "Should not be able to acquire an already held lock"
    );

    // Step 3: Drop the lock to release it
    drop(lock);

    // Step 4: Check the lock doesn't exist anymore (can acquire it again)
    let new_lock = backend
        .acquire("test_key")
        .await
        .expect("Should be able to acquire lock after it was released");
    // Clean up
    drop(new_lock);
}
