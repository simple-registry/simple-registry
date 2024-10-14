use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::registry::LinkReference;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BlobReferenceIndex {
    pub namespace: HashMap<String, HashSet<LinkReference>>,
}
