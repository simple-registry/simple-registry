use std::sync::Arc;
use cel_interpreter::{Context, Program, Value};
use chrono::Utc;
use tracing::debug;
use crate::command::Error;
use crate::policy::ManifestImage;

/// Checks if a rule validates and if therefore the specified manifest should be purged
///
/// # Returns
/// - `true` if the manifest should be purged
/// - `false` if the manifest should be retained
pub fn manifest_should_be_purged(rules: &[Program], manifest: ManifestImage, last_pushed: &Vec<String>, last_pulled: &Vec<String>) -> Result<bool, Error> {
    let mut context = Context::default();
    debug!("Policy context (image) : {:?}", manifest);

    context.add_variable("image", &manifest)?;
    context.add_variable("last_pushed", &last_pushed)?;
    context.add_variable("last_pulled", &last_pulled)?;

    context.add_function("now", || Utc::now().timestamp());
    context.add_function("days", |d: i64| d * 86400);
    context.add_function("top",  |s: Arc<String>, collection: Arc<Vec<Value>>, k: i64| {
        let mut i = 0;
        for e in collection.iter() {
            let Value::String(e) = e else {
                continue
            };

            if e.as_str() == s.as_str() {
                return true;
            }
            i += 1;
            if i >= k {
                break;
            }
        }

        false
    });

    for policy in rules {
        let evaluation_result = policy.execute(&context)?;

        debug!(
                "CEL program '{:?}' evaluates to {:?}",
                policy, evaluation_result
            );
        match evaluation_result {
            Value::Bool(true) => {
                debug!("Retention policy matched");
                return Ok(false);
            }
            Value::Bool(false) => { // Not validated, continue checking
            }
            _ => {
                debug!("Not eligible for cleanup");
                return Ok(false);
            }
        }
    }

    Ok(!rules.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_policy_no_rules() {
        let policies = vec![];
        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(!manifest_should_be_purged(&policies, manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_retention_policy_not_purged() {
        let policies = vec![
            Program::compile("image.tag == 'latest'").unwrap(),
        ];
        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(!manifest_should_be_purged(&policies, manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_retention_policy_purged() {
        let policies = vec![
            Program::compile("image.tag == 'latest'").unwrap(),
        ];
        let manifest = ManifestImage {
            tag: Some("x".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(manifest_should_be_purged(&policies, manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_retention_policy_invalid() {
        let policies = vec![
            Program::compile("image.tag").unwrap(),
        ];
        let manifest = ManifestImage {
            tag: None,
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(!manifest_should_be_purged(&policies, manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_function_now_days() {
        let policies = vec![
            Program::compile("now() + days(15) == now() + 86400 * 15").unwrap(),
        ];
        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };

        assert!(!manifest_should_be_purged(&policies, manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_function_top_last_pushed() {
        let policies = vec![
            Program::compile("top(image.tag, last_pushed, 1)").unwrap(),
        ];

        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };

        assert!(!manifest_should_be_purged(&policies, manifest, &vec!["latest".to_string()], &vec![]).unwrap());

        let manifest = ManifestImage {
            tag: Some("x".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(manifest_should_be_purged(&policies, manifest, &vec!["latest".to_string()], &vec![]).unwrap());
    }

    #[test]
    fn test_function_top_last_pulled() {
        let policies = vec![
            Program::compile("top(image.tag, last_pulled, 1)").unwrap(),
        ];

        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };

        assert!(!manifest_should_be_purged(&policies, manifest, &vec![], &vec!["latest".to_string()]).unwrap());

        let manifest = ManifestImage {
            tag: Some("x".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(manifest_should_be_purged(&policies, manifest, &vec![], &vec!["latest".to_string()]).unwrap());
    }
}
