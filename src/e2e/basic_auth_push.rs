use super::util::{hash_password, DockerCli, RegistryFixture, REGISTRY_PORT};

const TEST_USERNAME: &str = "testuser";
const TEST_PASSWORD: &str = "test";
const TEST_REPO: &str = "test";
const TEST_IMG: &str = "docker.io/hello-world:latest";

#[tokio::test]
#[ignore]
async fn test_basic_auth_push() {
    let mut docker = DockerCli::init();
    let mut ctx = RegistryFixture::new();
    let password_hash = hash_password(TEST_PASSWORD);

    let config_str = format!(
        r#"
[server]
bind_address = "0.0.0.0"
port = {REGISTRY_PORT}

[blob_store.fs]
root_dir = "{}"

[metadata_store.fs]
root_dir = "{}"

[cache.memory]

[global]
update_pull_time = false
max_concurrent_cache_jobs = 10
require_authentication = true

[auth.identity.test_user]
username = "{TEST_USERNAME}"
password = "{password_hash}"

[repository.{TEST_REPO}.access_policy]
default_allow = false
rules = [
    'identity.id == "test_user"'
]
"#,
        ctx.blobs_dir.display(),
        ctx.metadata_dir.display()
    );

    let config = toml::from_str(&config_str).expect("Invalid toml");
    ctx.start(config).await;

    docker.pull(TEST_IMG).await.unwrap();

    let tagged = format!("{}/{TEST_REPO}/testimg:latest", ctx.registry_url);
    docker.tag(TEST_IMG, &tagged).await.unwrap();
    docker
        .login(&ctx.registry_url, TEST_USERNAME, TEST_PASSWORD)
        .await
        .unwrap();
    docker.push(&tagged).await.unwrap();

    let response = ctx
        .http_client()
        .get(ctx.api_url(&format!("{TEST_REPO}/testimg/tags/list")))
        .basic_auth(TEST_USERNAME, Some(TEST_PASSWORD))
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert!(body.contains("latest"), "Tag not found: {body}");
}
