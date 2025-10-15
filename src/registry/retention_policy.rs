//! Retention policy evaluation for manifest cleanup.
//!
//! This module provides CEL-based retention policies for automatic manifest cleanup.
//! Policies are pre-compiled at configuration load time for performance.
//!
//! # Policy Evaluation
//!
//! Retention policies determine which manifests should be kept. If any rule
//! matches, the manifest is retained. Otherwise, it is eligible for deletion.
//!
//! # Available Variables
//!
//! CEL expressions have access to:
//! - `image`: Manifest information (`tag`, `pushed_at`, `last_pulled_at`)
//! - `last_pushed`: List of tags ordered by push time (most recent first)
//! - `last_pulled`: List of tags ordered by pull time (most recent first)
//!
//! # Helper Functions
//!
//! - `now()`: Current timestamp in seconds since epoch
//! - `days(n)`: Convert days to seconds
//! - `hours(n)`: Convert hours to seconds
//! - `minutes(n)`: Convert minutes to seconds
//! - `top(tag, list, n)`: Check if tag is in top N of list
//! - `size(list)`: Get size of a list

use crate::configuration::Error;
use cel_interpreter::{Context, Program, Value};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;

/// Configuration for retention policies.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RetentionPolicyConfig {
    #[serde(default)]
    pub rules: Vec<String>,
}

/// Manifest image information used in retention decisions.
#[derive(Debug, Default, Serialize)]
pub struct ManifestImage {
    pub tag: Option<String>,
    pub pushed_at: i64,
    pub last_pulled_at: i64,
}

/// Retention policy engine.
///
/// Evaluates CEL expressions to determine if manifests should be retained.
/// Rules are pre-compiled at configuration time for better performance.
pub struct RetentionPolicy {
    rules: Vec<Program>,
}

impl RetentionPolicy {
    /// Creates a new retention policy from configuration.
    ///
    /// Compiles CEL expressions from the configuration into programs.
    pub fn new(config: &RetentionPolicyConfig) -> Result<Self, Error> {
        let mut compiled_rules = Vec::new();

        for (index, rule) in config.rules.iter().enumerate() {
            match Program::compile(rule) {
                Ok(program) => compiled_rules.push(program),
                Err(e) => {
                    let msg = Error::Initialization(format!(
                        "Failed to compile retention policy rule #{} '{rule}': {e}",
                        index + 1
                    ));
                    return Err(msg);
                }
            }
        }

        Ok(Self {
            rules: compiled_rules,
        })
    }

    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }
    /// Evaluates whether a manifest should be retained.
    ///
    /// # Arguments
    /// * `manifest` - The manifest image information
    /// * `last_pushed` - List of recently pushed tags (most recent first)
    /// * `last_pulled` - List of recently pulled tags (most recent first)
    ///
    /// # Returns
    /// * `Ok(true)` if the manifest should be retained
    /// * `Ok(false)` if the manifest can be deleted
    /// * `Err` if policy evaluation fails
    pub fn should_retain(
        &self,
        manifest: &ManifestImage,
        last_pushed: &[String],
        last_pulled: &[String],
    ) -> Result<bool, Error> {
        if self.rules.is_empty() {
            return Ok(true);
        }

        let context = Self::build_context(manifest, last_pushed, last_pulled)?;

        for rule in &self.rules {
            match rule.execute(&context) {
                Ok(Value::Bool(true)) => {
                    debug!("Retention rule matched");
                    return Ok(true);
                }
                Ok(Value::Bool(false)) => {}
                _ => {
                    debug!("Retention rule did not evaluate to a boolean, retaining");
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn build_context<'a>(
        manifest: &'a ManifestImage,
        last_pushed: &'a [String],
        last_pulled: &'a [String],
    ) -> Result<Context<'a>, Error> {
        let mut context = Context::default();

        context
            .add_variable("image", manifest)
            .map_err(|e| Error::Initialization(e.to_string()))?;
        context
            .add_variable("last_pushed", last_pushed)
            .map_err(|e| Error::Initialization(e.to_string()))?;
        context
            .add_variable("last_pulled", last_pulled)
            .map_err(|e| Error::Initialization(e.to_string()))?;

        context.add_function("now", || Utc::now().timestamp());
        context.add_function("days", |d: i64| d * 86400);
        context.add_function("hours", |h: i64| h * 3600);
        context.add_function("minutes", |m: i64| m * 60);

        context.add_function(
            "top",
            |tag: Arc<String>, tags: Arc<Vec<Value>>, count: i64| {
                let limit = usize::try_from(count.max(0)).unwrap_or(usize::MAX);
                tags.iter()
                    .take(limit)
                    .any(|v| matches!(v, Value::String(s) if s.as_str() == tag.as_str()))
            },
        );

        context.add_function("size", |collection: Arc<Vec<Value>>| {
            i64::try_from(collection.len()).unwrap_or(i64::MAX)
        });

        Ok(context)
    }
}
