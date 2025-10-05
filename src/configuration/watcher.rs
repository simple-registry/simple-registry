use crate::command::server;
use crate::configuration::registry::create_registry;
use crate::configuration::{Configuration, ServerConfig};
use crate::registry::server::listeners::tls::ServerTlsConfig;
use crate::registry::server::ServerContext;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info};

pub struct ConfigWatcher {
    _handle: tokio::task::JoinHandle<()>,
}

impl ConfigWatcher {
    pub fn new(
        config_path: &str,
        server: Arc<server::Command>,
    ) -> Result<Self, crate::command::Error> {
        info!("Setting up config watcher for: {}", config_path);

        let config_file_path = std::fs::canonicalize(PathBuf::from(config_path))?;
        let config_path_clone = config_file_path.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = watch_config_loop(config_path_clone, server).await {
                error!("Config watcher failed: {}", e);
            }
        });

        Ok(Self { _handle: handle })
    }
}

fn get_tls_paths(tls_config: &ServerTlsConfig, config_dir: &Path) -> Vec<PathBuf> {
    [
        Some(&tls_config.server_certificate_bundle),
        Some(&tls_config.server_private_key),
        tls_config.client_ca_bundle.as_ref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|path_str| {
        let path = Path::new(path_str);
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            config_dir.join(path)
        };
        resolved.canonicalize().ok()
    })
    .collect()
}

async fn watch_config_loop(
    config_path: PathBuf,
    server: Arc<server::Command>,
) -> Result<(), crate::command::Error> {
    use notify::event::ModifyKind;
    use tokio::sync::mpsc;

    let (tx, mut rx) = mpsc::channel::<Event>(100);

    loop {
        let config_dir = config_path.parent().unwrap_or(Path::new("."));
        let mut watched_tls_paths = HashSet::new();

        let tx_clone = tx.clone();
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx_clone.blocking_send(event);
            }
        })?;

        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

        let current_config = Configuration::load(&config_path)?;

        if let ServerConfig::Tls(tls_config) = &current_config.server {
            for path in get_tls_paths(&tls_config.tls, config_dir) {
                watcher.watch(&path, RecursiveMode::NonRecursive)?;
                info!("Watching TLS file: {:?}", path);
                watched_tls_paths.insert(path);
            }
        }

        let mut should_restart_watcher = false;

        while !should_restart_watcher {
            match rx.recv().await {
                Some(event)
                    if matches!(
                        event.kind,
                        EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Any)
                    ) =>
                {
                    if event.paths.iter().any(|p| p == &config_path) {
                        info!("Configuration file changed, reloading");

                        let Ok(new_config) = Configuration::load(&config_path) else {
                            error!("Failed to reload configuration");
                            continue;
                        };

                        if let ServerConfig::Tls(tls_config) = &new_config.server {
                            let new_tls_paths: HashSet<_> =
                                get_tls_paths(&tls_config.tls, config_dir)
                                    .into_iter()
                                    .collect();
                            if new_tls_paths != watched_tls_paths {
                                info!("TLS file paths changed, recreating watchers");
                                should_restart_watcher = true;
                            }
                        }

                        reload_full_config(&server, &config_path, &new_config);
                    } else if event.paths.iter().any(|p| watched_tls_paths.contains(p)) {
                        info!("TLS certificate changed, reloading");
                        reload_tls_only(&server, &config_path);
                    }
                }
                None => {
                    error!("Config watcher channel closed");
                    return Ok(());
                }
                _ => {}
            }
        }

        drop(watcher);
    }
}

fn reload_full_config(server: &Arc<server::Command>, _config_path: &Path, config: &Configuration) {
    let Ok(oidc_validators) =
        ServerContext::build_oidc_validators(&config.auth.oidc, &config.cache)
    else {
        error!("Failed to build OIDC validators");
        return;
    };

    let Ok(registry) = create_registry(
        &config.global,
        &config.blob_store,
        config.metadata_store.clone(),
        config.repository.clone(),
        &config.cache,
        &config.auth,
    ) else {
        error!("Failed to create registry with new configuration");
        return;
    };

    if let Err(e) = server.notify_config_change(
        &config.server,
        &config.auth.identity,
        registry,
        oidc_validators,
    ) {
        error!("Failed to notify server of configuration change: {e}");
    } else {
        info!("Configuration reloaded");
    }
}

fn reload_tls_only(server: &Arc<server::Command>, config_path: &Path) {
    let Ok(config) = Configuration::load(config_path) else {
        return;
    };

    if let ServerConfig::Tls(tls_config) = config.server {
        if server.notify_tls_config_change(&tls_config.tls).is_ok() {
            info!("TLS configuration reloaded");
        }
    }
}
