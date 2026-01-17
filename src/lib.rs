pub mod executor;
pub mod h2client;
pub mod http;
pub mod provider;
pub mod websocket;
pub mod worker;

use std::borrow::Cow;
use std::fmt::Formatter;
use std::fs;
use std::io;
use std::ops::Deref;
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
    let mut value: serde_yaml::Value = serde_yaml::from_str(&config_str)?;
    // Parse YAML and apply merge anchors (<<: *alias) before deserializing to Config.
    // See: https://github.com/dtolnay/serde-yaml/issues/317
    value.apply_merge()?;
    let merged_yaml = serde_yaml::to_string(&value)?;
    let config: Config = serde_yaml::from_str(&merged_yaml)?;
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
        let _ = guard.shutdown_tx.send(());
        *guard = np;
    }
    Ok(())
}

pub async fn force_update_config(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    load_config(path, false).await
}

/// Gracefully shutdown the server by sending shutdown signal to all connections.
/// Existing connections will be allowed to complete before the process exits.
pub async fn graceful_shutdown() {
    let p = program();
    let guard = p.read().await;
    let _ = guard.shutdown_tx.send(());
    let timeout = guard.graceful_shutdown_timeout;
    log::info!(timeout = timeout; "graceful_shutdown_signal_sent");
    drop(guard);
    tokio::time::sleep(tokio::time::Duration::from_secs(timeout)).await;
}

struct Program {
    tls_server_config: Option<Arc<rustls::ServerConfig>>,
    https_port: Option<u16>,
    https_bind_address: String,
    http_port: Option<u16>,
    http_bind_address: String,
    http_max_header_size: usize,
    enable_health_check: bool,
    health_check_interval: u64,
    graceful_shutdown_timeout: u64,
    connect_tunnel_enabled: bool,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    providers: Arc<Vec<Box<dyn Provider>>>,
}

impl Program {
    fn from_config(mut config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate configuration: at least one of https_port or http_port must be set
        let https_port = config.https_port;
        let http_port = config.http_port;

        // For backwards compatibility, if neither port is specified but cert files exist, default to HTTPS on 443
        let (https_port, http_port) = match (
            https_port,
            http_port,
            &config.cert_file,
            &config.private_key_file,
        ) {
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
            let private_key_file = config
                .private_key_file
                .ok_or("private_key_file is required for HTTPS")?;

            if !Path::new(cert_file.as_ref()).exists() {
                return Err(format!("Certificate file not found: {}", cert_file).into());
            }
            if !Path::new(private_key_file.as_ref()).exists() {
                return Err(format!("Private key file not found: {}", private_key_file).into());
            }
            let certs = CertificateDer::pem_file_iter(cert_file.as_ref())?
                .collect::<Result<Vec<_>, _>>()?;
            let private_key = PrivateKeyDer::from_pem_file(private_key_file.as_ref())?;
            let mut tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)?;
            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Some(Arc::new(tls_config))
        } else {
            None
        };

        let auth_keys = Arc::new(config.auth_keys.unwrap_or_default());
        let mut providers = Vec::new();
        config.providers.sort_by(|a, b| a.host.cmp(&b.host));
        for mut provider in config.providers {
            let mut api_keys = provider.api_keys;
            api_keys.append(provider.api_key);
            if let Some(api_key_configs @ [_, _, ..]) = api_keys.as_deref() {
                debug_assert!(api_key_configs.len() > 1);
                let health_check_config = provider.health_check_config.take();
                for api_key_config in api_key_configs {
                    providers.push(new_provider(
                        &provider.kind,
                        &provider.host,
                        &provider.endpoint,
                        provider.port,
                        provider.tls.unwrap_or(true),
                        api_key_config
                            .weight
                            .unwrap_or(provider.weight.unwrap_or(1.0)),
                        Some(&api_key_config.key),
                        Arc::clone(&auth_keys),
                        provider.provider_auth_keys.clone(),
                        health_check_config.clone(),
                        provider.is_fallback,
                    )?);
                }
            } else {
                let api_key_config = api_keys.pop();
                providers.push(new_provider(
                    &provider.kind,
                    &provider.host,
                    &provider.endpoint,
                    provider.port,
                    provider.tls.unwrap_or(true),
                    api_key_config
                        .as_ref()
                        .and_then(|cfg| cfg.weight)
                        .unwrap_or(provider.weight.unwrap_or(1.0)),
                    api_key_config.as_ref().map(|cfg| cfg.key.as_ref()),
                    Arc::clone(&auth_keys),
                    provider.provider_auth_keys.clone(),
                    provider.health_check_config.take(),
                    provider.is_fallback,
                )?);
            }
        }
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        // Determine health check settings: new config takes precedence over deprecated fields
        let (enable_health_check, health_check_interval) = match &config.health_check {
            Some(hc) => (
                hc.enabled.unwrap_or(false),
                hc.interval
                    .unwrap_or(config.health_check_interval.unwrap_or(60)),
            ),
            // Only enable if health_check_interval is explicitly set (backwards compatibility)
            None => (
                config.health_check_interval.is_some(),
                config.health_check_interval.unwrap_or(60),
            ),
        };

        Ok(Self {
            tls_server_config,
            https_port,
            https_bind_address: config
                .https_bind_address
                .map(Cow::into_owned)
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            http_port,
            http_bind_address: config
                .http_bind_address
                .map(Cow::into_owned)
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            http_max_header_size: config
                .http_max_header_size
                .map(|size| size.max(1024).min(1024 * 1024))
                .unwrap_or(4096),
            enable_health_check,
            health_check_interval,
            graceful_shutdown_timeout: config.graceful_shutdown_timeout.unwrap_or(5),
            connect_tunnel_enabled: config.connect_tunnel_enabled,
            shutdown_tx,
            providers: Arc::new(providers),
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
                selected.then_some(&**provider)
            })
            .collect();

        // Separate non-fallback and fallback providers
        let (non_fallback, fallback): (Vec<_>, Vec<_>) = healthy_providers
            .into_iter()
            .partition(|p| !p.is_fallback());

        // Prefer non-fallback providers; only use fallback if no non-fallback providers exist
        let candidates = if non_fallback.is_empty() {
            fallback
        } else {
            non_fallback
        };

        match candidates.len() {
            0 => None,
            1 => Some(candidates[0]),
            _ => {
                let dist = WeightedIndex::new(candidates.iter().map(|p| p.weight()))
                    .expect("Failed to create WeightedIndex: invalid weights detected");
                let selected_idx = rng().sample(&dist);
                Some(candidates[selected_idx])
            }
        }
    }

    /// Select a provider with authentication during selection.
    /// This method tries to authenticate with each matching provider and returns
    /// the first one that authenticates successfully.
    ///
    /// The authentication order is:
    /// 1. Try all non-fallback providers first (with weighted random selection)
    /// 2. If all non-fallback providers fail authentication, try fallback providers
    /// 3. If all providers fail authentication, return None
    ///
    /// Returns a tuple of (provider, auth_type) where auth_type is the type returned
    /// by authenticate_with_type (e.g., "x-api-key" or "bearer").
    pub fn select_provider_with_auth<F>(
        &self,
        host: &str,
        path: &str,
        authenticate: F,
    ) -> Result<(&dyn Provider, Option<&'static str>), provider::AuthenticationError>
    where
        F: Fn(&dyn Provider) -> Result<Option<&'static str>, provider::AuthenticationError>,
    {
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
                selected.then_some(&**provider)
            })
            .collect();

        if healthy_providers.is_empty() {
            return Err(provider::AuthenticationError);
        }

        // First, authenticate all providers and collect those that pass
        let authenticated_providers: Vec<_> = healthy_providers
            .into_iter()
            .filter_map(|provider| match authenticate(provider) {
                Ok(auth_type) => Some((provider, auth_type)),
                Err(_) => None,
            })
            .collect();

        if authenticated_providers.is_empty() {
            return Err(provider::AuthenticationError);
        }

        // Separate authenticated providers into non-fallback and fallback
        let (non_fallback, fallback): (Vec<_>, Vec<_>) = authenticated_providers
            .into_iter()
            .partition(|(p, _)| !p.is_fallback());

        // Prefer non-fallback providers; only use fallback if no non-fallback providers authenticated
        let candidates = if non_fallback.is_empty() {
            fallback
        } else {
            non_fallback
        };

        // Select one provider based on weight
        match candidates.len() {
            0 => Err(provider::AuthenticationError),
            1 => Ok(candidates.into_iter().next().unwrap()),
            _ => {
                let dist = WeightedIndex::new(candidates.iter().map(|(p, _)| p.weight()))
                    .expect("Failed to create WeightedIndex: invalid weights detected");
                let selected_idx = rng().sample(&dist);
                Ok(candidates.into_iter().nth(selected_idx).unwrap())
            }
        }
    }
}

#[derive(Copy, Clone, serde::Serialize, serde::Deserialize)]
struct HealthCheckGlobalConfig {
    enabled: Option<bool>,
    interval: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Config<'a> {
    #[serde(skip_serializing)]
    #[serde(borrow)]
    cert_file: Option<Cow<'a, str>>,
    #[serde(skip_serializing)]
    #[serde(borrow)]
    private_key_file: Option<Cow<'a, str>>,
    /// Port for HTTPS connections (requires cert_file and private_key_file)
    https_port: Option<u16>,
    /// Bind address for HTTPS connections (default: 0.0.0.0)
    #[serde(borrow)]
    https_bind_address: Option<Cow<'a, str>>,
    /// Port for HTTP connections (HTTP/1.1 only, no TLS)
    http_port: Option<u16>,
    /// Bind address for HTTP connections (default: 0.0.0.0)
    #[serde(borrow)]
    http_bind_address: Option<Cow<'a, str>>,
    /// Maximum header size for HTTP connections (default: 4096)
    http_max_header_size: Option<usize>,
    #[serde(skip_serializing)]
    auth_keys: Option<Vec<String>>,
    /// Global health check configuration
    health_check: Option<HealthCheckGlobalConfig>,
    /// [DEPRECATED] Use health_check.interval instead
    health_check_interval: Option<u64>,
    /// Graceful shutdown timeout in seconds (default: 5)
    graceful_shutdown_timeout: Option<u64>,
    /// Enable CONNECT tunnel support (default: false)
    #[serde(default)]
    connect_tunnel_enabled: bool,
    /// Providers configuration
    #[serde(borrow)]
    providers: Vec<ProviderConfig<'a>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProviderConfig<'a> {
    #[serde(rename = "type")]
    #[serde(borrow)]
    kind: Cow<'a, str>,
    #[serde(borrow)]
    host: Cow<'a, str>,
    #[serde(borrow)]
    endpoint: Cow<'a, str>,
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
    /// If true, this provider is a fallback and will only be used when no other providers are available
    #[serde(default)]
    is_fallback: bool,
}

trait APIKeysTrait<'a> {
    type Item;
    fn pop(&mut self) -> Option<Self::Item>;
    fn append(&mut self, others: Option<APIKeys<'a>>);
}

#[derive(serde::Serialize, serde::Deserialize)]
struct APIKeyConfig<'a> {
    #[serde(skip_serializing)]
    #[serde(borrow)]
    key: Cow<'a, str>,
    weight: Option<f64>,
}

impl<'a> APIKeysTrait<'a> for Option<Vec<APIKeyConfig<'a>>> {
    type Item = APIKeyConfig<'a>;

    fn pop(&mut self) -> Option<APIKeyConfig<'a>> {
        self.get_or_insert_with(Vec::new).pop()
    }

    fn append(&mut self, others: Option<APIKeys<'a>>) {
        if let Some(APIKeys(others)) = others {
            for key in others {
                self.get_or_insert_with(Vec::new)
                    .push(APIKeyConfig { key, weight: None });
            }
        }
    }
}

struct APIKeys<'a>(Vec<Cow<'a, str>>);

impl<'a> Deref for APIKeys<'a> {
    type Target = [Cow<'a, str>];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

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
                Ok(APIKeys(vec![Cow::Borrowed(v)]))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(APIKeys(vec![Cow::Owned(v.to_owned())]))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(APIKeys(vec![Cow::Owned(v)]))
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                serde::Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
                    .map(APIKeys)
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

    #[error("Invalid server name: {0}")]
    InvalidServerName(String),

    #[error("No provider found")]
    NoProviderFound,

    #[error("Dynamic authentication failed")]
    DynamicAuthFailed,
}

use executor::{Executor, Pool};
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use worker::{Conn, Worker};

/// Create a TCP listener with SO_REUSEPORT enabled for hot upgrade support
#[cfg(unix)]
fn create_reuse_port_listener(
    bind_address: &str,
    port: u16,
) -> Result<std::net::TcpListener, Error> {
    let addr: SocketAddr = format!("{}:{}", bind_address, port).parse().unwrap();
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Create a TCP listener for non-Unix platforms (without SO_REUSEPORT)
#[cfg(not(unix))]
fn create_reuse_port_listener(
    bind_address: &str,
    port: u16,
) -> Result<std::net::TcpListener, Error> {
    let addr: SocketAddr = format!("{}:{}", bind_address, port).parse().unwrap();
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Start the proxy server with the configured listeners
///
/// # Arguments
///
/// * `cli_enable_health_check` - If true, enables health check via command line flag (deprecated).
///   This overrides the config file setting. Use `health_check.enabled: true` in config instead.
///
/// # Errors
///
/// Returns an error if the listener fails to bind to the configured port.
/// This can happen if:
/// - The port is already in use
/// - The process lacks permission to bind to the port
/// - The address is invalid
#[must_use = "this `Result` must be handled to detect listener bind failures"]
pub async fn serve(version: &str, cli_enable_health_check: bool) -> Result<(), Error> {
    let executor = Arc::new(Executor::new(Pool::new()));
    let (https_port, https_bind_address, http_port, http_bind_address, config_enable_health_check) = {
        let p = program();
        let guard = p.read().await;
        (
            guard.https_port,
            guard.https_bind_address.clone(),
            guard.http_port,
            guard.http_bind_address.clone(),
            guard.enable_health_check,
        )
    };

    log::info!(
        version = version,
        https_port = https_port,
        https_bind_address = https_bind_address,
        http_port = http_port,
        http_bind_address = http_bind_address,
        debug = cfg!(debug_assertions);
        "start_openproxy",
    );

    // CLI flag takes precedence for backwards compatibility (deprecated)
    let enable_health_check = cli_enable_health_check || config_enable_health_check;
    if enable_health_check {
        executor.run_health_check::<Worker<Pool<Conn>>>();
    }

    // Start HTTPS listener if configured
    if let Some(port) = https_port {
        let executor = Arc::clone(&executor);
        let std_listener = create_reuse_port_listener(&https_bind_address, port)?;
        let listener = TcpListener::from_std(std_listener)?;
        tokio::spawn(async move {
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
        let std_listener = create_reuse_port_listener(&http_bind_address, port)?;
        let listener = TcpListener::from_std(std_listener)?;
        tokio::spawn(async move {
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_invalid_server_name() {
        let err = Error::InvalidServerName("invalid.endpoint".to_string());
        assert_eq!(err.to_string(), "Invalid server name: invalid.endpoint");

        // Verify the error contains the problematic endpoint name
        let err = Error::InvalidServerName("my-custom-endpoint:443".to_string());
        assert!(err.to_string().contains("my-custom-endpoint:443"));
    }

    #[test]
    fn test_error_display() {
        // Test all error variants have proper Display impl
        let io_err = Error::IO(std::io::Error::new(std::io::ErrorKind::Other, "test"));
        assert!(io_err.to_string().contains("IO error"));

        let header_err = Error::HeaderTooLarge;
        assert_eq!(header_err.to_string(), "Header too large");

        let invalid_header = Error::InvalidHeader;
        assert_eq!(invalid_header.to_string(), "Invalid header");

        let no_provider = Error::NoProviderFound;
        assert_eq!(no_provider.to_string(), "No provider found");

        let dynamic_auth_failed = Error::DynamicAuthFailed;
        assert_eq!(
            dynamic_auth_failed.to_string(),
            "Dynamic authentication failed"
        );
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err: Error = io_err.into();
        match err {
            Error::IO(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused),
            _ => panic!("Expected IO error"),
        }
    }

    #[test]
    fn test_fallback_provider_not_selected_when_non_fallback_available() {
        let auth_keys = Arc::new(vec![]);
        let providers: Vec<Box<dyn provider::Provider>> = vec![
            provider::new_provider(
                "openai",
                "api.openai.com",
                "api.openai.com",
                None,
                true,
                1.0,
                Some("sk-test"),
                Arc::clone(&auth_keys),
                None,
                None,
                false, // non-fallback
            )
            .unwrap(),
            provider::new_provider(
                "openai",
                "api.openai.com",
                "fallback.openai.com",
                None,
                true,
                1.0,
                Some("sk-fallback"),
                Arc::clone(&auth_keys),
                None,
                None,
                true, // fallback
            )
            .unwrap(),
        ];

        let program = Program {
            tls_server_config: None,
            https_port: None,
            http_port: Some(8080),
            https_bind_address: "0.0.0.0".to_string(),
            http_bind_address: "0.0.0.0".to_string(),
            http_max_header_size: 4096,
            enable_health_check: false,
            health_check_interval: 0,
            graceful_shutdown_timeout: 5,
            connect_tunnel_enabled: false,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            providers: Arc::new(providers),
        };

        // Run multiple times to ensure fallback is never selected
        for _ in 0..100 {
            let selected = program
                .select_provider("api.openai.com", "/v1/chat")
                .unwrap();
            assert_eq!(
                selected.endpoint(),
                "api.openai.com",
                "Fallback provider should not be selected when non-fallback is available"
            );
            assert!(!selected.is_fallback());
        }
    }

    #[test]
    fn test_fallback_provider_selected_when_only_fallbacks_available() {
        let auth_keys = Arc::new(vec![]);
        let providers: Vec<Box<dyn provider::Provider>> = vec![
            provider::new_provider(
                "openai",
                "api.openai.com",
                "fallback1.openai.com",
                None,
                true,
                1.0,
                Some("sk-fallback1"),
                Arc::clone(&auth_keys),
                None,
                None,
                true, // fallback
            )
            .unwrap(),
            provider::new_provider(
                "openai",
                "api.openai.com",
                "fallback2.openai.com",
                None,
                true,
                1.0,
                Some("sk-fallback2"),
                Arc::clone(&auth_keys),
                None,
                None,
                true, // fallback
            )
            .unwrap(),
        ];

        let program = Program {
            tls_server_config: None,
            https_port: None,
            http_port: Some(8080),
            https_bind_address: "0.0.0.0".to_string(),
            http_bind_address: "0.0.0.0".to_string(),
            http_max_header_size: 4096,
            enable_health_check: false,
            health_check_interval: 0,
            graceful_shutdown_timeout: 5,
            connect_tunnel_enabled: false,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            providers: Arc::new(providers),
        };

        let selected = program.select_provider("api.openai.com", "/v1/chat");
        assert!(
            selected.is_some(),
            "Should select a fallback when only fallbacks exist"
        );
        assert!(selected.unwrap().is_fallback());
    }

    #[test]
    fn test_fallback_provider_selected_when_non_fallback_unhealthy() {
        let auth_keys = Arc::new(vec![]);
        let providers: Vec<Box<dyn provider::Provider>> = vec![
            provider::new_provider(
                "openai",
                "api.openai.com",
                "api.openai.com",
                None,
                true,
                1.0,
                Some("sk-test"),
                Arc::clone(&auth_keys),
                None,
                None,
                false, // non-fallback
            )
            .unwrap(),
            provider::new_provider(
                "openai",
                "api.openai.com",
                "fallback.openai.com",
                None,
                true,
                1.0,
                Some("sk-fallback"),
                Arc::clone(&auth_keys),
                None,
                None,
                true, // fallback
            )
            .unwrap(),
        ];

        // Mark non-fallback as unhealthy
        providers[0].set_healthy(false);

        let program = Program {
            tls_server_config: None,
            https_port: None,
            http_port: Some(8080),
            https_bind_address: "0.0.0.0".to_string(),
            http_bind_address: "0.0.0.0".to_string(),
            http_max_header_size: 4096,
            enable_health_check: false,
            health_check_interval: 0,
            graceful_shutdown_timeout: 5,
            connect_tunnel_enabled: false,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            providers: Arc::new(providers),
        };

        let selected = program.select_provider("api.openai.com", "/v1/chat");
        assert!(
            selected.is_some(),
            "Should select fallback when non-fallback is unhealthy"
        );
        assert_eq!(selected.unwrap().endpoint(), "fallback.openai.com");
        assert!(selected.unwrap().is_fallback());
    }

    #[test]
    fn test_select_provider_with_auth_selects_authenticated_provider() {
        let auth_keys = Arc::new(vec!["valid-key".to_string()]);
        let providers: Vec<Box<dyn provider::Provider>> = vec![
            provider::new_provider(
                "openai",
                "api.openai.com",
                "provider1.openai.com",
                None,
                true,
                1.0,
                Some("sk-test1"),
                Arc::clone(&auth_keys),
                Some(vec!["key-for-provider1".to_string()]),
                None,
                false,
            )
            .unwrap(),
            provider::new_provider(
                "openai",
                "api.openai.com",
                "provider2.openai.com",
                None,
                true,
                1.0,
                Some("sk-test2"),
                Arc::clone(&auth_keys),
                Some(vec!["key-for-provider2".to_string()]),
                None,
                false,
            )
            .unwrap(),
        ];

        let program = Program {
            tls_server_config: None,
            https_port: None,
            http_port: Some(8080),
            https_bind_address: "0.0.0.0".to_string(),
            http_bind_address: "0.0.0.0".to_string(),
            http_max_header_size: 4096,
            enable_health_check: false,
            health_check_interval: 0,
            graceful_shutdown_timeout: 5,
            connect_tunnel_enabled: false,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            providers: Arc::new(providers),
        };

        // Test with key valid for provider1
        let auth_header = b"Authorization: Bearer key-for-provider1";
        let result = program.select_provider_with_auth("api.openai.com", "/v1/chat", |provider| {
            provider.authenticate_with_type(Some(auth_header))
        });
        assert!(result.is_ok());
        let (provider, _) = result.unwrap();
        assert_eq!(provider.endpoint(), "provider1.openai.com");

        // Test with key valid for provider2
        let auth_header = b"Authorization: Bearer key-for-provider2";
        let result = program.select_provider_with_auth("api.openai.com", "/v1/chat", |provider| {
            provider.authenticate_with_type(Some(auth_header))
        });
        assert!(result.is_ok());
        let (provider, _) = result.unwrap();
        assert_eq!(provider.endpoint(), "provider2.openai.com");

        // Test with key valid for both (global auth_keys)
        let auth_header = b"Authorization: Bearer valid-key";
        let result = program.select_provider_with_auth("api.openai.com", "/v1/chat", |provider| {
            provider.authenticate_with_type(Some(auth_header))
        });
        assert!(result.is_ok());
        // Should select one of the two providers
        let (provider, _) = result.unwrap();
        assert!(
            provider.endpoint() == "provider1.openai.com"
                || provider.endpoint() == "provider2.openai.com"
        );

        // Test with invalid key
        let auth_header = b"Authorization: Bearer invalid-key";
        let result = program.select_provider_with_auth("api.openai.com", "/v1/chat", |provider| {
            provider.authenticate_with_type(Some(auth_header))
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_select_provider_with_auth_tries_fallback_after_non_fallback() {
        let auth_keys = Arc::new(vec![]);
        let providers: Vec<Box<dyn provider::Provider>> = vec![
            provider::new_provider(
                "openai",
                "api.openai.com",
                "primary.openai.com",
                None,
                true,
                1.0,
                Some("sk-primary"),
                Arc::clone(&auth_keys),
                Some(vec!["key-for-primary".to_string()]),
                None,
                false, // non-fallback
            )
            .unwrap(),
            provider::new_provider(
                "openai",
                "api.openai.com",
                "fallback.openai.com",
                None,
                true,
                1.0,
                Some("sk-fallback"),
                Arc::clone(&auth_keys),
                Some(vec!["key-for-fallback".to_string()]),
                None,
                true, // fallback
            )
            .unwrap(),
        ];

        let program = Program {
            tls_server_config: None,
            https_port: None,
            http_port: Some(8080),
            https_bind_address: "0.0.0.0".to_string(),
            http_bind_address: "0.0.0.0".to_string(),
            http_max_header_size: 4096,
            enable_health_check: false,
            health_check_interval: 0,
            graceful_shutdown_timeout: 5,
            connect_tunnel_enabled: false,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            providers: Arc::new(providers),
        };

        // Test with key only valid for fallback
        // Non-fallback should be tried first, fail, then fallback should be selected
        let auth_header = b"Authorization: Bearer key-for-fallback";
        let result = program.select_provider_with_auth("api.openai.com", "/v1/chat", |provider| {
            provider.authenticate_with_type(Some(auth_header))
        });
        assert!(result.is_ok());
        let (provider, _) = result.unwrap();
        assert_eq!(provider.endpoint(), "fallback.openai.com");
        assert!(provider.is_fallback());

        // Test with key only valid for primary
        // Primary should be selected first since it's non-fallback
        let auth_header = b"Authorization: Bearer key-for-primary";
        let result = program.select_provider_with_auth("api.openai.com", "/v1/chat", |provider| {
            provider.authenticate_with_type(Some(auth_header))
        });
        assert!(result.is_ok());
        let (provider, _) = result.unwrap();
        assert_eq!(provider.endpoint(), "primary.openai.com");
        assert!(!provider.is_fallback());
    }

    #[test]
    fn test_select_provider_with_auth_no_matching_providers() {
        let auth_keys = Arc::new(vec!["valid-key".to_string()]);
        let providers: Vec<Box<dyn provider::Provider>> = vec![provider::new_provider(
            "openai",
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("sk-test"),
            Arc::clone(&auth_keys),
            None,
            None,
            false,
        )
        .unwrap()];

        let program = Program {
            tls_server_config: None,
            https_port: None,
            http_port: Some(8080),
            https_bind_address: "0.0.0.0".to_string(),
            http_bind_address: "0.0.0.0".to_string(),
            http_max_header_size: 4096,
            enable_health_check: false,
            health_check_interval: 0,
            graceful_shutdown_timeout: 5,
            connect_tunnel_enabled: false,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            providers: Arc::new(providers),
        };

        // Test with non-matching host
        let auth_header = b"Authorization: Bearer valid-key";
        let result =
            program.select_provider_with_auth("api.different.com", "/v1/chat", |provider| {
                provider.authenticate_with_type(Some(auth_header))
            });
        assert!(result.is_err());
    }

    #[test]
    fn test_select_provider_with_auth_no_auth_keys_required() {
        let auth_keys = Arc::new(vec![]); // No auth keys required
        let providers: Vec<Box<dyn provider::Provider>> = vec![provider::new_provider(
            "openai",
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("sk-test"),
            Arc::clone(&auth_keys),
            None, // No provider auth keys
            None,
            false,
        )
        .unwrap()];

        let program = Program {
            tls_server_config: None,
            https_port: None,
            http_port: Some(8080),
            https_bind_address: "0.0.0.0".to_string(),
            http_bind_address: "0.0.0.0".to_string(),
            http_max_header_size: 4096,
            enable_health_check: false,
            health_check_interval: 0,
            graceful_shutdown_timeout: 5,
            connect_tunnel_enabled: false,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            providers: Arc::new(providers),
        };

        // Without auth keys, any authentication should pass
        let result = program.select_provider_with_auth("api.openai.com", "/v1/chat", |provider| {
            provider.authenticate_with_type(None)
        });
        assert!(result.is_ok());

        // Even with invalid key, should pass since no auth is required
        let auth_header = b"Authorization: Bearer any-key";
        let result = program.select_provider_with_auth("api.openai.com", "/v1/chat", |provider| {
            provider.authenticate_with_type(Some(auth_header))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_http_max_header_size_default_value() {
        let yaml = r#"
http_port: 8080
providers:
  - type: openai
    host: api.openai.com
    endpoint: api.openai.com
    api_key: sk-test
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let program = Program::from_config(config).unwrap();
        assert_eq!(program.http_max_header_size, 4096);
    }

    #[test]
    fn test_http_max_header_size_custom_value() {
        let yaml = r#"
http_port: 8080
http_max_header_size: 8192
providers:
  - type: openai
    host: api.openai.com
    endpoint: api.openai.com
    api_key: sk-test
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let program = Program::from_config(config).unwrap();
        assert_eq!(program.http_max_header_size, 8192);
    }

    #[test]
    fn test_http_max_header_size_large_value() {
        let yaml = r#"
http_port: 8080
http_max_header_size: 65536
providers:
  - type: openai
    host: api.openai.com
    endpoint: api.openai.com
    api_key: sk-test
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let program = Program::from_config(config).unwrap();
        assert_eq!(program.http_max_header_size, 65536);
    }

    #[test]
    fn test_http_max_header_size_clamped_to_minimum() {
        let yaml = r#"
http_port: 8080
http_max_header_size: 512
providers:
  - type: openai
    host: api.openai.com
    endpoint: api.openai.com
    api_key: sk-test
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let program = Program::from_config(config).unwrap();
        // Should be clamped to minimum 1024
        assert_eq!(program.http_max_header_size, 1024);
    }

    #[test]
    fn test_http_max_header_size_clamped_to_maximum() {
        let yaml = r#"
http_port: 8080
http_max_header_size: 2097152
providers:
  - type: openai
    host: api.openai.com
    endpoint: api.openai.com
    api_key: sk-test
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let program = Program::from_config(config).unwrap();
        // Should be clamped to maximum 1MB (1024 * 1024 = 1048576)
        assert_eq!(program.http_max_header_size, 1024 * 1024);
    }

    #[test]
    fn test_http_max_header_size_at_boundaries() {
        // Test at minimum boundary (1024)
        let yaml = r#"
http_port: 8080
http_max_header_size: 1024
providers:
  - type: openai
    host: api.openai.com
    endpoint: api.openai.com
    api_key: sk-test
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let program = Program::from_config(config).unwrap();
        assert_eq!(program.http_max_header_size, 1024);

        // Test at maximum boundary (1MB)
        let yaml = r#"
http_port: 8080
http_max_header_size: 1048576
providers:
  - type: openai
    host: api.openai.com
    endpoint: api.openai.com
    api_key: sk-test
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let program = Program::from_config(config).unwrap();
        assert_eq!(program.http_max_header_size, 1048576);
    }

    #[test]
    fn test_yaml_merge_anchor() {
        // Test that YAML merge anchors work correctly
        let yaml = r#"
defaults: &defaults
  tls: true
  port: 443
  weight: 1.0

http_port: 8080

providers:
  - type: "openai"
    host: "api.openai.com"
    endpoint: "api.openai.com"
    api_key: "sk-test"
    <<: *defaults
"#;

        let mut value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        value.apply_merge().unwrap();
        let merged_yaml = serde_yaml::to_string(&value).unwrap();
        let config: Config = serde_yaml::from_str(&merged_yaml).unwrap();

        assert_eq!(config.http_port, Some(8080));
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].tls, Some(true));
        assert_eq!(config.providers[0].port, Some(443));
        assert_eq!(config.providers[0].weight, Some(1.0));
    }

    #[test]
    fn test_yaml_merge_anchor_with_dynamic_auth_key() {
        // Test that YAML merge anchors work with dynamic auth keys (quoted strings)
        // This tests the case where serde_yaml::to_string() changes the quote style
        let yaml = r#"
defaults: &defaults
  tls: true
  port: 443

http_port: 8080

providers:
  - type: "anthropic"
    host: "claude.ai"
    endpoint: "claude.ai"
    api_key: "$(/usr/bin/jq -r '.claudeAiOauth.accessToken' /root/.claude/.credentials.json # x)"
    <<: *defaults
"#;

        let mut value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        value.apply_merge().unwrap();
        let merged_yaml = serde_yaml::to_string(&value).unwrap();
        let config: Config = serde_yaml::from_str(&merged_yaml).unwrap();

        assert_eq!(config.http_port, Some(8080));
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].tls, Some(true));
        assert_eq!(config.providers[0].port, Some(443));
        // Verify the dynamic auth key is preserved correctly
        let api_keys = config.providers[0].api_key.as_ref().unwrap();
        assert_eq!(
            api_keys[0],
            "$(/usr/bin/jq -r '.claudeAiOauth.accessToken' /root/.claude/.credentials.json # x)"
        )
    }

    #[test]
    fn test_yaml_merge_anchor_with_api_keys_array() {
        // Test YAML merge anchors with api_keys array containing dynamic auth
        let yaml = r#"
defaults: &defaults
  tls: true
  port: 443

http_port: 8080

providers:
  - type: "anthropic"
    host: "claude.ai"
    endpoint: "claude.ai"
    api_keys:
      - key: "$(/usr/bin/jq -r '.accessToken' /path/to/creds.json)"
        weight: 1.0
    <<: *defaults
"#;

        let mut value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        value.apply_merge().unwrap();
        let merged_yaml = serde_yaml::to_string(&value).unwrap();
        let config: Config = serde_yaml::from_str(&merged_yaml).unwrap();

        assert_eq!(config.http_port, Some(8080));
        assert_eq!(config.providers.len(), 1);
        let api_keys = config.providers[0].api_keys.as_ref().unwrap();
        assert_eq!(
            api_keys[0].key,
            "$(/usr/bin/jq -r '.accessToken' /path/to/creds.json)"
        )
    }
}
