use crate::cache::{Cache, Error, SerializingCache};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct StubCache {
    storage: Arc<Mutex<StubStorage>>,
}

#[derive(Debug)]
struct StubStorage {
    data: Option<String>,
    retrieve_error: Option<String>,
    store_error: Option<String>,
}

impl StubCache {
    fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(StubStorage {
                data: None,
                retrieve_error: None,
                store_error: None,
            })),
        }
    }

    fn set_data(&self, data: Option<String>) {
        self.storage.lock().unwrap().data = data;
    }

    fn set_retrieve_error(&self, error: Option<String>) {
        self.storage.lock().unwrap().retrieve_error = error;
    }

    fn set_store_error(&self, error: Option<String>) {
        self.storage.lock().unwrap().store_error = error;
    }

    fn get_stored_data(&self) -> Option<String> {
        self.storage.lock().unwrap().data.clone()
    }
}

#[async_trait]
impl Cache for StubCache {
    async fn store_value(&self, _key: &str, value: &str, _expires_in: u64) -> Result<(), Error> {
        let mut storage = self.storage.lock().unwrap();
        if let Some(error) = &storage.store_error {
            return Err(Error::Backend(error.clone()));
        }
        storage.data = Some(value.to_string());
        Ok(())
    }

    async fn retrieve_value(&self, _key: &str) -> Result<Option<String>, Error> {
        let storage = self.storage.lock().unwrap();
        if let Some(error) = &storage.retrieve_error {
            return Err(Error::Backend(error.clone()));
        }
        Ok(storage.data.clone())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestData {
    name: String,
    value: i32,
}

#[tokio::test]
async fn test_retrieve_success() {
    let cache = StubCache::new();
    let test_data = TestData {
        name: "test".to_string(),
        value: 42,
    };
    let serialized = serde_json::to_string(&test_data).unwrap();
    cache.set_data(Some(serialized));

    let cache_trait: &dyn Cache = &cache;
    let result: Result<Option<TestData>, Error> = cache_trait.retrieve("test_key").await;

    assert!(result.is_ok());
    let retrieved = result.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), test_data);
}

#[tokio::test]
async fn test_retrieve_not_found() {
    let cache = StubCache::new();
    cache.set_data(None);

    let cache_trait: &dyn Cache = &cache;
    let result: Result<Option<TestData>, Error> = cache_trait.retrieve("test_key").await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_retrieve_backend_error() {
    let cache = StubCache::new();
    cache.set_retrieve_error(Some("Backend failure".to_string()));

    let cache_trait: &dyn Cache = &cache;
    let result: Result<Option<TestData>, Error> = cache_trait.retrieve("test_key").await;

    assert!(matches!(result, Err(Error::Execution(_))));
}

#[tokio::test]
async fn test_retrieve_deserialization_error() {
    let cache = StubCache::new();
    cache.set_data(Some("invalid json".to_string()));

    let cache_trait: &dyn Cache = &cache;
    let result: Result<Option<TestData>, Error> = cache_trait.retrieve("test_key").await;

    assert!(matches!(result, Err(Error::Execution(_))));
}

#[tokio::test]
async fn test_store_success() {
    let cache = StubCache::new();
    let test_data = TestData {
        name: "test".to_string(),
        value: 42,
    };

    let cache_trait: &dyn Cache = &cache;
    let result = cache_trait.store("test_key", &test_data, 60).await;

    assert!(result.is_ok());

    let stored = cache.get_stored_data();
    assert!(stored.is_some());
    let deserialized: TestData = serde_json::from_str(&stored.unwrap()).unwrap();
    assert_eq!(deserialized, test_data);
}

#[tokio::test]
async fn test_store_backend_error() {
    let cache = StubCache::new();
    cache.set_store_error(Some("Backend failure".to_string()));

    let test_data = TestData {
        name: "test".to_string(),
        value: 42,
    };

    let cache_trait: &dyn Cache = &cache;
    let result = cache_trait.store("test_key", &test_data, 60).await;

    assert!(matches!(result, Err(Error::Execution(_))));
}

#[derive(Debug, Serialize)]
struct UnserializableData {
    #[serde(serialize_with = "fail_serialization")]
    value: i32,
}

fn fail_serialization<S>(_: &i32, _: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    Err(serde::ser::Error::custom(
        "Intentional serialization failure",
    ))
}

#[tokio::test]
async fn test_store_serialization_error() {
    let cache = StubCache::new();
    let bad_data = UnserializableData { value: 42 };

    let cache_trait: &dyn Cache = &cache;
    let result = cache_trait.store("test_key", &bad_data, 60).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        Error::Execution(msg) => {
            assert!(msg.contains("Failed to serialize value for caching"));
        }
        _ => panic!("Expected Execution error"),
    }
}
