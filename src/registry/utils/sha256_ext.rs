use crate::registry::data_store::Error;
use crate::registry::oci_types;
use sha2::digest::crypto_common::hazmat::SerializableState;
use sha2::{Digest, Sha256};

pub trait Sha256Ext {
    fn serialized_empty_state() -> Vec<u8>;
    fn serialize_state(&self) -> Vec<u8>;
    fn deserialize_state(state: &[u8]) -> Result<Sha256, Error>;
    fn to_digest(self) -> oci_types::Digest;
}

impl Sha256Ext for Sha256 {
    fn serialized_empty_state() -> Vec<u8> {
        let state = Self::new();
        let state = state.serialize();
        state.as_slice().to_vec()
    }

    fn serialize_state(&self) -> Vec<u8> {
        let state = self.serialize();
        state.as_slice().to_vec()
    }

    fn deserialize_state(state: &[u8]) -> Result<Sha256, Error> {
        let state = state
            .try_into()
            .map_err(|_| Error::HashSerialization("Unable to resume hash state".to_string()))?;
        let state = Sha256::deserialize(state)?;
        let hasher = Sha256::from(state);

        Ok(hasher)
    }

    fn to_digest(self) -> oci_types::Digest {
        let hash = self.finalize();
        let digest = hex::encode(hash.as_slice());
        oci_types::Digest::Sha256(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[tokio::test]
    async fn test_hash_serialization() {
        let mut empty_state = Sha256::new();
        empty_state.update(b"hello world");
        let empty_state = empty_state.serialize_state();

        let state =
            Sha256::deserialize_state(&empty_state).expect("Failed to deserialize hash state");
        let state = state.serialize_state();

        assert_eq!(empty_state, state);
    }
}
