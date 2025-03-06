use crate::command;
use argh::FromArgs;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Params, PasswordHasher, Version};

#[derive(FromArgs, PartialEq, Debug)]
#[allow(clippy::struct_excessive_bools)]
#[argh(
    subcommand,
    name = "argon",
    description = "Hash a password following the argon2id algorithm"
)]
pub struct Options {}

pub struct Command {}

impl Command {
    pub fn run() -> Result<(), command::Error> {
        let password = rpassword::prompt_password("Input Password: ")?;

        let salt = SaltString::generate(OsRng);

        let config = Params::default();
        let argon = argon2::Argon2::new(Algorithm::Argon2id, Version::V0x13, config);
        let hash = argon.hash_password(password.as_bytes(), &salt).unwrap();

        println!("{hash}");
        Ok(())
    }
}
