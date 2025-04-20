use crate::registry::utils::BlobLink;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub namespace: HashMap<String, HashSet<BlobLink>>,
}
