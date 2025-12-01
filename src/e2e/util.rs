use crate::command::server::Command as ServerCommand;
use crate::configuration::Configuration;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

pub const REGISTRY_PORT: u16 = 8080;
pub const REGISTRY_HOST: &str = "localhost";
pub const SERVER_STARTUP_GRACE_MS: u64 = 1_000;

pub struct DockerCli {
    registry_url: Option<String>,
    images_to_remove: Vec<String>,
}

impl DockerCli {
    pub fn init() -> Self {
        let available = Command::new("docker")
            .args(["info"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !available {
            panic!(
                "Docker is not available. Please install Docker and ensure the daemon is running."
            );
        }

        Self {
            registry_url: None,
            images_to_remove: Vec::new(),
        }
    }

    pub async fn run(&self, args: &[&str]) -> Result<String, String> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        tokio::task::spawn_blocking(move || {
            let output = Command::new("docker")
                .args(&args)
                .output()
                .map_err(|e| format!("Failed to execute docker: {e}"))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                return Err(format!(
                    "Docker command failed:\nstdout: {stdout}\nstderr: {stderr}"
                ));
            }

            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        })
        .await
        .map_err(|e| format!("Task join error: {e}"))?
    }

    pub async fn pull(&self, image: &str) -> Result<(), String> {
        self.run(&["pull", image]).await?;
        Ok(())
    }

    pub async fn tag(&mut self, source: &str, target: &str) -> Result<(), String> {
        self.run(&["tag", source, target]).await?;
        self.images_to_remove.push(target.to_string());
        Ok(())
    }

    pub async fn push(&self, image: &str) -> Result<(), String> {
        self.run(&["push", image]).await?;
        Ok(())
    }

    pub async fn login(
        &mut self,
        registry_url: &str,
        username: &str,
        password: &str,
    ) -> Result<(), String> {
        let registry = registry_url.to_string();
        let user = username.to_string();
        let pass = password.to_string();

        self.registry_url = Some(registry.clone());

        tokio::task::spawn_blocking(move || {
            let mut child = Command::new("docker")
                .args(["login", &registry, "-u", &user, "--password-stdin"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("Failed to spawn docker login: {e}"))?;

            {
                let stdin = child.stdin.as_mut().expect("Failed to open stdin");
                stdin
                    .write_all(pass.as_bytes())
                    .map_err(|e| format!("Failed to write password: {e}"))?;
            }

            let output = child
                .wait_with_output()
                .map_err(|e| format!("Failed to wait for docker login: {e}"))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                return Err(format!(
                    "Docker login failed:\nstdout: {stdout}\nstderr: {stderr}"
                ));
            }

            Ok(())
        })
        .await
        .map_err(|e| format!("Task join error: {e}"))?
    }
}

impl Drop for DockerCli {
    fn drop(&mut self) {
        for image in &self.images_to_remove {
            let _ = Command::new("docker").args(["rmi", image]).output();
        }

        if let Some(ref registry) = self.registry_url {
            let _ = Command::new("docker").args(["logout", registry]).output();
        }
    }
}

struct ServerGuard {
    handle: JoinHandle<()>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub struct RegistryFixture {
    _data_dir: tempfile::TempDir,
    _server_guard: Option<ServerGuard>,
    pub registry_url: String,
    pub blobs_dir: std::path::PathBuf,
    pub metadata_dir: std::path::PathBuf,
}

impl RegistryFixture {
    pub fn new() -> Self {
        let data_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let blobs_dir = data_dir.path().join("blobs");
        let metadata_dir = data_dir.path().join("metadata");

        std::fs::create_dir_all(&blobs_dir).expect("Failed to create blobs dir");
        std::fs::create_dir_all(&metadata_dir).expect("Failed to create metadata dir");

        Self {
            _data_dir: data_dir,
            _server_guard: None,
            registry_url: format!("{REGISTRY_HOST}:{REGISTRY_PORT}"),
            blobs_dir,
            metadata_dir,
        }
    }

    pub async fn start(&mut self, config: Configuration) {
        let server = Arc::new(ServerCommand::new(&config).expect("Failed to create server"));

        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(Duration::from_millis(SERVER_STARTUP_GRACE_MS)).await;
        self._server_guard = Some(ServerGuard { handle });
    }

    pub fn http_client(&self) -> reqwest::Client {
        reqwest::Client::new()
    }

    pub fn api_url(&self, path: &str) -> String {
        format!(
            "http://{}/v2/{}",
            self.registry_url,
            path.trim_start_matches('/')
        )
    }
}
