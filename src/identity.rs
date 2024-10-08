use std::collections::HashSet;

pub struct Identity {
    pub identity_id: String,
    pub authorized_repositories: HashSet<String>,
}
