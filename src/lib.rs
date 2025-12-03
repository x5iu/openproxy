pub mod executor;
pub mod http;
pub mod provider;
pub mod worker;

use std::fmt::Formatter;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Once};

use rand::distr::weighted::WeightedIndex;
use rand::{rng, Rng};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use serde::de::SeqAccess;
use serde::Deserializer;
use structured_logger::json::new_writer;
use tokio::sync::{OnceCell, RwLock};

use provider::{new_provider, Provider};

static PROGRAM: OnceCell<Arc<RwLock<Program>>> = OnceCell::const_new();

fn program() -> Arc<RwLock<Program>> {
    Arc::clone(PROGRAM.get().unwrap())
}

pub async fn load_config(
    path: impl AsRef<Path>,
    first_load: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = fs::read_to_string(&path)?;
    let config: Config = serde_yaml::from_str(&config_str)?;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        structured_logger::Builder::with_level("INFO")
            .with_target_writer("openproxy*", new_writer(io::stderr()))
            .init();
    });
    log::info!(config:serde = config; "load_config");
    let np = Program::from_config(config)?;
    if first_load {
        if let Err(e) = PROGRAM.set(Arc::new(RwLock::new(np))) {
            log::error!(error = e.to_string(); "load_config_error");
            std::process::exit(2);
        }
    } else {
        let p = program();
        let mut guard = p.write().await;
        // Send shutdown signal to existing tasks before updating config
        if let Err(e) = guard.shutdown_tx.send(()) {
            log::warn!(error = e.to_string(); "no_active_listeners_for_shutdown_signal");
        }
        *guard = np;
    }
    Ok(())
}

pub async fn force_update_config(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    load_config(path, false).await
}

struct Program {
    tls_server_config: Option<Arc<rustls::ServerConfig>>,
    https_port: Option<u16>,
    http_port: Option<u16>,
    providers: Arc<Vec<Box<dyn Provider>>>,
    health_check_interval: u64,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl Program {
    fn from_config(mut config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate configuration: at least one of https_port or http_port must be set
        let https_port = config.https_port;
        let http_port = config.http_port;

        // For backwards compatibility, if neither port is specified but cert files exist, default to HTTPS on 443
        let (https_port, http_port) = match (https_port, http_port, &config.cert_file, &config.private_key_file) {
            (None, None, Some(_), Some(_)) => (Some(443), None),
            (None, None, None, None) => {
                return Err("Either https_port (with cert_file and private_key_file) or http_port must be configured".into());
            }
            (Some(_), _, None, _) | (Some(_), _, _, None) => {
                return Err("https_port requires both cert_file and private_key_file".into());
            }
            (https, http, _, _) => (https, http),
        };

        // Load TLS configuration if HTTPS is enabled
        let tls_server_config = if https_port.is_some() {
            let cert_file = config.cert_file.ok_or("cert_file is required for HTTPS")?;
            let private_key_file = config.private_key_file.ok_or("private_key_file is required for HTTPS")?;

            if !Path::new(cert_file).exists() {
                return Err(format!("Certificate file not found: {}", cert_file).into());
            }
            if !Path::new(private_key_file).exists() {
                return Err(format!("Private key file not found: {}", private_key_file).into());
            }
            let certs =
                CertificateDer::pem_file_iter(cert_file)?.collect::<Result<Vec<_>, _>>()?;
            let private_key = PrivateKeyDer::from_pem_file(private_key_file)?;
            let mut tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)?;
            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Some(Arc::new(tls_config))
        } else {
            None
        };

        let auth_keys = Arc::new(config.auth_keys.unwrap_or_else(Vec::new));
        let mut providers = Vec::new();
        config.providers.sort_by_key(|provider| provider.host);
        for mut provider in config.providers {
            let mut api_keys = provider.api_keys;

            // Extend from single key if present
            if let Some(single_key) = provider.api_key {
                api_keys.extend_from_single(single_key);
            }

            if let Some(api_key_configs @ [_, _, ..]) = api_keys.as_deref() {
                debug_assert!(api_key_configs.len() > 1);
                let health_check_config = provider.health_check_config.take();
                for api_key_config in api_key_configs {
                    providers.push(new_provider(
                        provider.kind,
                        provider.host,
                        provider.endpoint,
                        provider.port,
                        provider.tls.unwrap_or(true),
                        api_key_config
                            .weight
                            .unwrap_or(provider.weight.unwrap_or(1.0)),
                        Some(api_key_config.key),
                        Arc::clone(&auth_keys),
                        provider.provider_auth_keys.clone(),
                        health_check_config.clone(),
                    )?);
                }
            } else {
                let api_key_config = api_keys.pop();
                providers.push(new_provider(
                    provider.kind,
                    provider.host,
                    provider.endpoint,
                    provider.port,
                    provider.tls.unwrap_or(true),
                    api_key_config
                        .as_ref()
                        .and_then(|cfg| cfg.weight)
                        .unwrap_or(provider.weight.unwrap_or(1.0)),
                    api_key_config.as_ref().map(|cfg| cfg.key),
                    Arc::clone(&auth_keys),
                    provider.provider_auth_keys.clone(),
                    provider.health_check_config.take(),
                )?);
            }
        }
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Ok(Self {
            tls_server_config,
            https_port,
            http_port,
            providers: Arc::new(providers),
            health_check_interval: config.health_check_interval.unwrap_or(60),
            shutdown_tx,
        })
    }

    pub fn select_provider(&self, host: &str, path: &str) -> Option<&dyn Provider> {
        // Strip port from incoming host for comparison
        let host_without_port = http::strip_port(host);
        let healthy_providers: Vec<&dyn Provider> = self
            .providers
            .iter()
            .filter_map(|provider| {
                if !provider.is_healthy() {
                    return None;
                }
                let (provider_host, provider_path_prefix) = http::split_host_path(provider.host());
                // Strip port from provider host for comparison
                let provider_host_without_port = http::strip_port(provider_host);
                let selected = if let Some(provider_path_prefix) = provider_path_prefix {
                    (provider_host == host || provider_host_without_port == host_without_port)
                        && path.starts_with(provider_path_prefix)
                        && matches!(
                            path.as_bytes().get(provider_path_prefix.len()),
                            None | Some(b'/')
                        )
                } else {
                    provider_host == host || provider_host_without_port == host_without_port
                };
                selected.then(|| &**provider)
            })
            .collect();

        match healthy_providers.len() {
            0 => None,
            1 => Some(healthy_providers[0]),
            _ => {
                let dist = WeightedIndex::new(healthy_providers.iter().map(|p| p.weight()))
                    .expect("Failed to create WeightedIndex: invalid weights detected");
                let selected_idx = rng().sample(&dist);
                Some(healthy_providers[selected_idx])
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Config<'a> {
    #[serde(skip_serializing)]
    cert_file: Option<&'a str>,
    #[serde(skip_serializing)]
    private_key_file: Option<&'a str>,
    /// Port for HTTPS connections (requires cert_file and private_key_file)
    https_port: Option<u16>,
    /// Port for HTTP connections (HTTP/1.1 only, no TLS)
    http_port: Option<u16>,
    providers: Vec<ProviderConfig<'a>>,
    #[serde(skip_serializing)]
    auth_keys: Option<Vec<String>>,
    health_check_interval: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProviderConfig<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    host: &'a str,
    endpoint: &'a str,
    port: Option<u16>,
    tls: Option<bool>,
    weight: Option<f64>,
    #[serde(skip_serializing)]
    #[serde(borrow)]
    api_key: Option<APIKeys<'a>>,
    #[serde(skip_serializing)]
    #[serde(borrow)]
    api_keys: Option<Vec<APIKeyConfig<'a>>>,
    #[serde(skip_serializing)]
    #[serde(rename = "auth_keys")]
    provider_auth_keys: Option<Vec<String>>,
    #[serde(rename = "health_check")]
    health_check_config: Option<provider::HealthCheckConfig>,
}

trait APIKeysTrait<'a> {
    type Item;
    fn pop(&mut self) -> Option<Self::Item>;
    fn extend_from_single(&mut self, keys: APIKeys<'a>);
    fn extend_from_multiple(&mut self, keys: Vec<&'a str>);
}

#[derive(serde::Serialize, serde::Deserialize)]
struct APIKeyConfig<'a> {
    #[serde(skip_serializing)]
    key: &'a str,
    weight: Option<f64>,
}

impl<'a> APIKeysTrait<'a> for Option<Vec<APIKeyConfig<'a>>> {
    type Item = APIKeyConfig<'a>;

    fn pop(&mut self) -> Option<APIKeyConfig<'a>> {
        self.get_or_insert_with(Vec::new).pop()
    }

    fn extend_from_single(&mut self, keys: APIKeys<'a>) {
        let vec = self.get_or_insert_with(Vec::new);
        for key in keys.0 {
            vec.push(APIKeyConfig { key, weight: None });
        }
    }

    fn extend_from_multiple(&mut self, keys: Vec<&'a str>) {
        let vec = self.get_or_insert_with(Vec::new);
        for key in keys {
            vec.push(APIKeyConfig { key, weight: None });
        }
    }
}

#[derive(serde::Deserialize)]
struct APIKeys<'a>(Vec<&'a str>);

impl<'de: 'a, 'a> serde::Deserialize<'de> for APIKeys<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = APIKeys<'de>;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("string or array of strings")
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(APIKeys(vec![v]))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut keys = Vec::new();
                while let Some(key) = seq.next_element::<&'de str>()? {
                    keys.push(key);
                }
                Ok(APIKeys(keys))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    IO(
        #[source]
        #[from]
        io::Error,
    ),

    #[error("TLS error: {0}")]
    TLS(
        #[source]
        #[from]
        rustls::Error,
    ),

    #[error("h2 error: {0}")]
    H2(
        #[source]
        #[from]
        h2::Error,
    ),

    #[error("Header too large")]
    HeaderTooLarge,

    #[error("Invalid header")]
    InvalidHeader,
}

use executor::{Executor, Pool};
use tokio::net::TcpListener;
use worker::{Conn, Worker};

/// Start the proxy server with the configured listeners
pub async fn serve(enable_health_check: bool) {
    let executor = Arc::new(Executor::new(Pool::new()));
    let (https_port, http_port) = {
        let p = program();
        let guard = p.read().await;
        (guard.https_port, guard.http_port)
    };
    log::info!(https_port = https_port, http_port = http_port, debug = cfg!(debug_assertions); "start_openproxy");

    if enable_health_check {
        executor.run_health_check::<Worker<Pool<Conn>>>();
    }

    // Start HTTPS listener if configured
    if let Some(port) = https_port {
        let executor = Arc::clone(&executor);
        tokio::spawn(async move {
            let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
                .await
                .unwrap();
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let executor = Arc::clone(&executor);
                        tokio::spawn(async move {
                            executor.execute::<Worker<Pool<Conn>>>(stream).await;
                        });
                    }
                    #[cfg_attr(not(debug_assertions), allow(unused))]
                    Err(e) => {
                        #[cfg(debug_assertions)]
                        log::error!(error = e.to_string(); "https_accept_error")
                    }
                }
            }
        });
    }

    // Start HTTP listener if configured (HTTP/1.1 only)
    if let Some(port) = http_port {
        let executor = Arc::clone(&executor);
        tokio::spawn(async move {
            let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
                .await
                .unwrap();
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let executor = Arc::clone(&executor);
                        tokio::spawn(async move {
                            executor.execute_http::<Worker<Pool<Conn>>>(stream).await;
                        });
                    }
                    #[cfg_attr(not(debug_assertions), allow(unused))]
                    Err(e) => {
                        #[cfg(debug_assertions)]
                        log::error!(error = e.to_string(); "http_accept_error")
                    }
                }
            }
        });
    }
}
