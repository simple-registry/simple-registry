use crate::configuration::{Error, RepositoryConfig};
use cel_interpreter::Program;

#[derive(Debug)]
pub struct Repository {
    pub access_default_allow: bool,
    pub access_rules: Vec<Program>,
}

impl Repository {
    pub fn new(config: &RepositoryConfig) -> Result<Self, Error> {
        let access_rules = Self::compile_program_vec(&config
            .access_policy
            .rules)?;

        Ok(Self {
            access_default_allow: config.access_policy.default_allow,
            access_rules,
        })
    }

    fn compile_program_vec(programs: &[String]) -> Result<Vec<Program>, Error> {
        Ok(programs
            .iter()
            .map(|policy| Program::compile(policy))
            .collect::<Result<Vec<Program>, _>>()?)
    }
}
