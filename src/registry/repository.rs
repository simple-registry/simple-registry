use crate::configuration::{Error, RepositoryConfig, RepositoryPullThroughConfig};
use cel_interpreter::Program;

#[derive(Debug)]
pub struct Repository {
    pub upstream: Vec<RepositoryPullThroughConfig>,
    pub access_default_allow: bool,
    pub access_rules: Vec<Program>,
    #[allow(dead_code)]
    pub retention_rules: Vec<Program>,
}

impl Repository {
    pub fn new(config: RepositoryConfig) -> Result<Self, Error> {
        let access_rules = Self::compile_program_vec(&config.access_policy.rules)?;

        let retention_rules = Self::compile_program_vec(&config.retention_policy.rules)?;

        Ok(Self {
            upstream: config.upstream,
            access_default_allow: config.access_policy.default_allow,
            access_rules,
            retention_rules,
        })
    }

    fn compile_program_vec(programs: &[String]) -> Result<Vec<Program>, Error> {
        Ok(programs
            .iter()
            .map(|policy| Program::compile(policy))
            .collect::<Result<Vec<Program>, _>>()?)
    }

    pub fn is_pull_through(&self) -> bool {
        !self.upstream.is_empty()
    }
}
