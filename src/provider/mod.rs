use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::http;

/// Constant-time string comparison to prevent timing attacks.
/// Returns true if the two strings are equal.
#[inline]
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    // Length check is not constant-time, but this is acceptable since
    // API key lengths are typically public knowledge (e.g., OpenAI keys are always 51 chars)
    a_bytes.len() == b_bytes.len() && bool::from(a_bytes.ct_eq(b_bytes))
}

#[allow(clippy::too_many_arguments)]
pub fn new_provider(
    kind: &str,
    host: &str,
    endpoint: &str,
    port: Option<u16>,
    tls: bool,
    weight: f64,
    api_key: Option<&str>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
    health_check_config: Option<HealthCheckConfig>,
) -> Result<Box<dyn Provider>, Box<dyn std::error::Error>> {
    match kind {
        "openai" => Ok(Box::new(OpenAIProvider::new(
            host,
            endpoint,
            port,
            tls,
            weight,
            api_key,
            auth_keys,
            provider_auth_keys,
            health_check_config,
        )?)),
        "gemini" => Ok(Box::new(GeminiProvider::new(
            host,
            endpoint,
            port,
            tls,
            weight,
            api_key,
            auth_keys,
            provider_auth_keys,
            health_check_config,
        )?)),
        "anthropic" => Ok(Box::new(AnthropicProvider::new(
            host,
            endpoint,
            port,
            tls,
            weight,
            api_key,
            auth_keys,
            provider_auth_keys,
            health_check_config,
        )?)),
        _ => Err(format!("Unsupported provider type: {:?}", kind).into()),
    }
}

pub enum Type {
    OpenAI,
    Gemini,
    Anthropic,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::OpenAI => write!(f, "openai"),
            Type::Gemini => write!(f, "gemini"),
            Type::Anthropic => write!(f, "anthropic"),
        }
    }
}

pub trait Provider: Send + Sync {
    fn kind(&self) -> Type;
    fn host(&self) -> &str;
    fn api_key(&self) -> Option<&str>;
    fn endpoint(&self) -> &str;
    fn server_name(&self) -> rustls_pki_types::ServerName<'static>;
    fn sock_address(&self) -> &str;
    fn host_header(&self) -> &str;
    fn auth_query_key(&self) -> Option<&'static str>;
    fn auth_header(&self) -> Option<&str>;
    fn auth_header_key(&self) -> Option<&'static str>;
    fn has_auth_keys(&self) -> bool;
    fn authenticate(&self, auth: Option<&[u8]>) -> Result<(), AuthenticationError>;
    fn authenticate_key(&self, key: &str) -> Result<(), AuthenticationError>;
    fn weight(&self) -> f64;

    /// Returns the path prefix that should be stripped from requests, if any.
    /// For example, if host is "localhost/openai", returns Some("/openai").
    fn path_prefix(&self) -> Option<&str> {
        let (_, prefix) = http::split_host_path(self.host());
        prefix
    }

    fn rewrite_first_header_block(&self, block: &[u8]) -> Option<Vec<u8>> {
        let Ok(block_str) = std::str::from_utf8(block) else {
            return None;
        };
        if let (_, Some(prefix)) = http::split_host_path(self.host()) {
            let block_cow_str = replace_path(prefix, block_str);
            Some(match block_cow_str {
                Cow::Borrowed(s) => s.to_string().into_bytes(),
                Cow::Owned(s) => s.into_bytes(),
            })
        } else {
            None
        }
    }

    fn tls(&self) -> bool {
        true
    }

    fn is_healthy(&self) -> bool;
    fn set_healthy(&self, healthy: bool);

    /// Returns true if this provider uses dynamic auth (e.g., OAuth)
    fn uses_dynamic_auth(&self) -> bool {
        false
    }

    /// Get dynamic auth header. Called per-request for providers that use dynamic auth.
    /// Returns the full auth header string (e.g., "Authorization: Bearer token\r\n")
    fn get_dynamic_auth_header(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Err("Dynamic auth not supported".into())
    }

    /// Returns the list of header keys that need to be transformed/replaced.
    /// For example, Anthropic OAuth needs to transform "anthropic-beta: " header.
    /// Each key should include the ": " suffix (e.g., "anthropic-beta: ").
    fn extra_headers(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Transform a header value for a given header key.
    /// Called for each header key returned by `extra_headers()`.
    ///
    /// - `header_key`: The header key (e.g., "anthropic-beta: ")
    /// - `existing_value`: The existing value if the header was present in the request
    ///
    /// Returns the new header line to add (should end with \r\n), or None to skip.
    fn transform_extra_header(&self, _header_key: &str, _existing_value: Option<&str>) -> Option<String> {
        None
    }

    #[allow(clippy::type_complexity)]
    fn health_check<'a: 'stream, 'stream>(
        &'a self,
        #[allow(unused)] stream: &'stream mut dyn AsyncReadWrite,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + 'stream>>
    {
        Box::pin(async move { Ok(()) })
    }
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthCheckConfig {
    method: Option<String>,
    path: String,
    body: Option<String>,
    headers: Option<Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
#[error("Authentication error")]
pub struct AuthenticationError;

pub struct OpenAIProvider {
    host: Arc<str>,
    api_key: Option<String>,
    endpoint: Arc<str>,
    tls: bool,
    weight: f64,
    host_header: String,
    auth_header: Option<String>,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
    is_healthy: AtomicBool,
    health_check_config: Option<HealthCheckConfig>,
}

impl OpenAIProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &str,
        endpoint: &str,
        port: Option<u16>,
        tls: bool,
        weight: f64,
        api_key: Option<&str>,
        auth_keys: Arc<Vec<String>>,
        provider_auth_keys: Option<Vec<String>>,
        health_check_config: Option<HealthCheckConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let host: Arc<str> = Arc::from(host);
        let endpoint: Arc<str> = Arc::from(endpoint);
        let server_name = rustls_pki_types::ServerName::try_from(endpoint.to_string())?;
        let port = port.unwrap_or(if tls { 443 } else { 80 });
        // Include port in Host header for non-standard ports (not 80 for HTTP, not 443 for HTTPS)
        let host_header = if (tls && port == 443) || (!tls && port == 80) {
            format!("Host: {}\r\n", endpoint)
        } else {
            format!("Host: {}:{}\r\n", endpoint, port)
        };
        let auth_header = api_key.map(|api_key| {
            format!("{}Bearer {}\r\n", http::HEADER_AUTHORIZATION, api_key)
        });
        let sock_address = format!("{}:{}", endpoint, port);
        Ok(Self {
            host,
            api_key: api_key.map(ToString::to_string),
            endpoint,
            tls,
            weight,
            host_header,
            auth_header,
            sock_address,
            server_name,
            auth_keys,
            provider_auth_keys,
            is_healthy: AtomicBool::new(true),
            health_check_config,
        })
    }
}

impl Provider for OpenAIProvider {
    fn kind(&self) -> Type {
        Type::OpenAI
    }

    fn host(&self) -> &str {
        &self.host
    }

    fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn server_name(&self) -> rustls_pki_types::ServerName<'static> {
        self.server_name.clone()
    }

    fn sock_address(&self) -> &str {
        &self.sock_address
    }

    fn host_header(&self) -> &str {
        &self.host_header
    }

    fn auth_query_key(&self) -> Option<&'static str> {
        None
    }

    fn auth_header(&self) -> Option<&str> {
        self.auth_header.as_deref()
    }

    fn auth_header_key(&self) -> Option<&'static str> {
        Some(http::HEADER_AUTHORIZATION)
    }

    fn has_auth_keys(&self) -> bool {
        !self.auth_keys.is_empty() || self.provider_auth_keys.is_some()
    }

    fn weight(&self) -> f64 {
        self.weight
    }

    fn authenticate(&self, header: Option<&[u8]>) -> Result<(), AuthenticationError> {
        if !self.has_auth_keys() {
            return Ok(());
        }
        let Some(header) = header else {
            return Err(AuthenticationError);
        };
        let Ok(header_str) = std::str::from_utf8(header) else {
            #[cfg(debug_assertions)]
            log::error!(provider = "openai", header:serde = header.to_vec(); "invalid_authentication_header");
            return Err(AuthenticationError);
        };
        #[cfg(debug_assertions)]
        log::info!(provider = "openai", header = header_str; "authentication");
        if !http::is_header(header_str, http::HEADER_AUTHORIZATION) {
            return Err(AuthenticationError);
        }
        self.authenticate_key(&header_str[http::HEADER_AUTHORIZATION.len()..])
    }

    fn authenticate_key(&self, key: &str) -> Result<(), AuthenticationError> {
        let input_key = key.trim_start_matches("Bearer ").trim();
        // Use constant-time comparison to prevent timing attacks
        self.auth_keys
            .iter()
            .chain(self.provider_auth_keys.iter().flatten())
            .find(|&k| constant_time_eq(k, input_key))
            .map(|_| ())
            .ok_or(AuthenticationError)
    }

    fn tls(&self) -> bool {
        self.tls
    }

    fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::SeqCst)
    }

    fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::SeqCst)
    }

    #[allow(clippy::type_complexity)]
    fn health_check<'a: 'stream, 'stream>(
        &'a self,
        stream: &'stream mut dyn AsyncReadWrite,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + 'stream>>
    {
        if let Some(ref cfg) = self.health_check_config {
            Box::pin(health_check(
                stream,
                self.endpoint().as_bytes(),
                cfg.method.as_ref().map(|v| v.as_bytes()).unwrap_or(b"GET"),
                cfg.path.as_bytes(),
                self.auth_header().map(|v| v.as_bytes()),
                cfg.headers
                    .as_deref()
                    .map(|v| v.iter().map(|x| x.trim().as_bytes())),
                cfg.body.as_ref().map(|v| v.as_bytes()).unwrap_or_default(),
            ))
        } else {
            Box::pin(async { Ok(()) })
        }
    }
}

pub struct GeminiProvider {
    host: Arc<str>,
    endpoint: Arc<str>,
    tls: bool,
    weight: f64,
    api_key: String,
    host_header: String,
    auth_header: String,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
    is_healthy: AtomicBool,
    health_check_config: Option<HealthCheckConfig>,
}

impl GeminiProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &str,
        endpoint: &str,
        port: Option<u16>,
        tls: bool,
        weight: f64,
        api_key: Option<&str>,
        auth_keys: Arc<Vec<String>>,
        provider_auth_keys: Option<Vec<String>>,
        health_check_config: Option<HealthCheckConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(api_key) = api_key else {
            return Err("gemini: missing `api_key`".into());
        };
        let host: Arc<str> = Arc::from(host);
        let endpoint: Arc<str> = Arc::from(endpoint);
        let server_name = rustls_pki_types::ServerName::try_from(endpoint.to_string())?;
        let port = port.unwrap_or(if tls { 443 } else { 80 });
        // Include port in Host header for non-standard ports
        let host_header = if (tls && port == 443) || (!tls && port == 80) {
            format!("Host: {}\r\n", endpoint)
        } else {
            format!("Host: {}:{}\r\n", endpoint, port)
        };
        let auth_header = format!("{}{}\r\n", http::HEADER_X_GOOG_API_KEY, api_key);
        let sock_address = format!("{}:{}", endpoint, port);
        Ok(GeminiProvider {
            host,
            endpoint,
            tls,
            weight,
            api_key: api_key.to_string(),
            host_header,
            auth_header,
            sock_address,
            server_name,
            auth_keys,
            provider_auth_keys,
            is_healthy: AtomicBool::new(true),
            health_check_config,
        })
    }
}

impl Provider for GeminiProvider {
    fn kind(&self) -> Type {
        Type::Gemini
    }

    fn host(&self) -> &str {
        &self.host
    }

    fn api_key(&self) -> Option<&str> {
        Some(self.api_key.as_str())
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn server_name(&self) -> rustls_pki_types::ServerName<'static> {
        self.server_name.clone()
    }

    fn sock_address(&self) -> &str {
        &self.sock_address
    }

    fn host_header(&self) -> &str {
        &self.host_header
    }

    fn auth_query_key(&self) -> Option<&'static str> {
        Some(http::QUERY_KEY_KEY)
    }

    fn auth_header(&self) -> Option<&str> {
        Some(&self.auth_header)
    }

    fn auth_header_key(&self) -> Option<&'static str> {
        Some(http::HEADER_X_GOOG_API_KEY)
    }

    fn has_auth_keys(&self) -> bool {
        !self.auth_keys.is_empty() || self.provider_auth_keys.is_some()
    }

    fn weight(&self) -> f64 {
        self.weight
    }

    fn authenticate(&self, key: Option<&[u8]>) -> Result<(), AuthenticationError> {
        if !self.has_auth_keys() {
            return Ok(());
        }
        let Some(key) = key else {
            return Err(AuthenticationError);
        };
        let Ok(mut key_str) = std::str::from_utf8(key) else {
            #[cfg(debug_assertions)]
            log::error!(provider = "gemini", key:serde = key.to_vec(); "invalid_authentication_key");
            return Err(AuthenticationError);
        };
        #[cfg(debug_assertions)]
        log::info!(provider = "gemini", key = key_str; "authentication");
        if http::is_header(key_str, http::HEADER_X_GOOG_API_KEY) {
            key_str = &key_str[http::HEADER_X_GOOG_API_KEY.len()..];
        }
        self.authenticate_key(key_str)
    }

    fn authenticate_key(&self, key: &str) -> Result<(), AuthenticationError> {
        let input_key = key.trim();
        // Use constant-time comparison to prevent timing attacks
        self.auth_keys
            .iter()
            .chain(self.provider_auth_keys.iter().flatten())
            .find(|&k| constant_time_eq(k, input_key))
            .map(|_| ())
            .ok_or(AuthenticationError)
    }

    fn rewrite_first_header_block(&self, block: &[u8]) -> Option<Vec<u8>> {
        let Ok(block_str) = std::str::from_utf8(block) else {
            return None;
        };
        let mut block_cow_str = Cow::Borrowed(block_str);
        if let (_, Some(prefix)) = http::split_host_path(self.host()) {
            block_cow_str = replace_path(prefix, block_str);
        }
        let query_range = http::get_auth_query_range(&block_cow_str, http::QUERY_KEY_KEY)?;
        let mut rewritten = Vec::with_capacity(block_cow_str.len());
        rewritten.extend_from_slice(block_cow_str[..query_range.start].as_bytes());
        rewritten.extend_from_slice(self.api_key.as_bytes());
        rewritten.extend_from_slice(block_cow_str[query_range.end..].as_bytes());
        Some(rewritten)
    }

    fn tls(&self) -> bool {
        self.tls
    }

    fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::SeqCst)
    }

    fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::SeqCst)
    }

    fn health_check<'a: 'stream, 'stream>(
        &'a self,
        stream: &'stream mut dyn AsyncReadWrite,
    ) -> Pin<Box<dyn Future<Output=Result<(), Box<dyn std::error::Error>>> + Send + 'stream>>
    {
        if let Some(ref cfg) = self.health_check_config {
            Box::pin(async move {
                let path = format!("{}?key={}", cfg.path, self.api_key);
                health_check(
                    stream,
                    self.endpoint().as_bytes(),
                    cfg.method.as_ref().map(|v| v.as_bytes()).unwrap_or(b"GET"),
                    path.as_bytes(),
                    None,
                    cfg.headers
                        .as_deref()
                        .map(|v| v.iter().map(|x| x.trim().as_bytes())),
                    cfg.body.as_ref().map(|v| v.as_bytes()).unwrap_or_default(),
                )
                    .await
            })
        } else {
            Box::pin(async move { Ok(()) })
        }
    }
}

pub struct AnthropicProvider {
    host: Arc<str>,
    api_key: String,
    endpoint: Arc<str>,
    tls: bool,
    weight: f64,
    host_header: String,
    /// Static auth header (for x-api-key style authentication)
    auth_header: Option<String>,
    /// Command to execute to get OAuth token (for Authorization Bearer style)
    oauth_command: Option<String>,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
    is_healthy: AtomicBool,
    health_check_config: Option<HealthCheckConfig>,
}

/// Check if the api_key is a command pattern like $(command)
fn is_oauth_command(api_key: &str) -> bool {
    api_key.starts_with("$(") && api_key.ends_with(')')
}

/// Extract the command from the $(command) pattern
fn extract_oauth_command(api_key: &str) -> Option<&str> {
    if is_oauth_command(api_key) {
        Some(&api_key[2..api_key.len() - 1])
    } else {
        None
    }
}

/// Execute a shell command and return the stdout as a string
fn execute_oauth_command(command: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("OAuth command failed: {}", stderr).into());
    }

    let token = String::from_utf8(output.stdout)?;
    Ok(token.trim().to_string())
}

impl AnthropicProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &str,
        endpoint: &str,
        port: Option<u16>,
        tls: bool,
        weight: f64,
        api_key: Option<&str>,
        auth_keys: Arc<Vec<String>>,
        provider_auth_keys: Option<Vec<String>>,
        health_check_config: Option<HealthCheckConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(api_key) = api_key else {
            return Err("anthropic: missing `api_key`".into());
        };
        let host: Arc<str> = Arc::from(host);
        let endpoint: Arc<str> = Arc::from(endpoint);
        let server_name = rustls_pki_types::ServerName::try_from(endpoint.to_string())?;
        let port = port.unwrap_or(if tls { 443 } else { 80 });
        // Include port in Host header for non-standard ports
        let host_header = if (tls && port == 443) || (!tls && port == 80) {
            format!("Host: {}\r\n", endpoint)
        } else {
            format!("Host: {}:{}\r\n", endpoint, port)
        };

        // Check if api_key is a command pattern for OAuth
        let (auth_header, oauth_command) = if let Some(cmd) = extract_oauth_command(api_key) {
            // OAuth mode: use Authorization Bearer header, execute command for each request
            (None, Some(cmd.to_string()))
        } else {
            // Standard mode: use X-API-Key header
            (Some(format!("{}{}\r\n", http::HEADER_X_API_KEY, api_key)), None)
        };

        let sock_address = format!("{}:{}", endpoint, port);
        Ok(Self {
            host,
            api_key: api_key.to_string(),
            endpoint,
            tls,
            weight,
            host_header,
            auth_header,
            oauth_command,
            sock_address,
            server_name,
            auth_keys,
            provider_auth_keys,
            is_healthy: AtomicBool::new(true),
            health_check_config,
        })
    }

    /// Check if this provider uses OAuth authentication
    pub fn uses_oauth(&self) -> bool {
        self.oauth_command.is_some()
    }

    /// Get the OAuth token by executing the command.
    /// Returns the Authorization header value.
    pub fn get_oauth_token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref cmd) = self.oauth_command {
            let token = execute_oauth_command(cmd)?;
            Ok(token)
        } else {
            Err("Not an OAuth provider".into())
        }
    }
}

impl Provider for AnthropicProvider {
    fn kind(&self) -> Type {
        Type::Anthropic
    }

    fn host(&self) -> &str {
        &self.host
    }

    fn api_key(&self) -> Option<&str> {
        Some(self.api_key.as_str())
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn server_name(&self) -> rustls_pki_types::ServerName<'static> {
        self.server_name.clone()
    }

    fn sock_address(&self) -> &str {
        &self.sock_address
    }

    fn host_header(&self) -> &str {
        &self.host_header
    }

    fn auth_query_key(&self) -> Option<&'static str> {
        None
    }

    fn auth_header(&self) -> Option<&str> {
        self.auth_header.as_deref()
    }

    fn auth_header_key(&self) -> Option<&'static str> {
        Some(http::HEADER_X_API_KEY)
    }

    fn has_auth_keys(&self) -> bool {
        !self.auth_keys.is_empty() || self.provider_auth_keys.is_some()
    }

    fn weight(&self) -> f64 {
        self.weight
    }

    fn authenticate(&self, header: Option<&[u8]>) -> Result<(), AuthenticationError> {
        if !self.has_auth_keys() {
            return Ok(());
        }
        let Some(header) = header else {
            return Err(AuthenticationError);
        };
        let Ok(header_str) = std::str::from_utf8(header) else {
            #[cfg(debug_assertions)]
            log::error!(provider = "anthropic", header:serde = header.to_vec(); "invalid_authentication_header");
            return Err(AuthenticationError);
        };
        #[cfg(debug_assertions)]
        log::info!(provider = "anthropic", header = header_str; "authentication");
        if !http::is_header(header_str, http::HEADER_X_API_KEY) {
            return Err(AuthenticationError);
        }
        self.authenticate_key(&header_str[http::HEADER_X_API_KEY.len()..])
    }

    fn authenticate_key(&self, key: &str) -> Result<(), AuthenticationError> {
        let input_key = key.trim();
        // Use constant-time comparison to prevent timing attacks
        self.auth_keys
            .iter()
            .chain(self.provider_auth_keys.iter().flatten())
            .find(|&k| constant_time_eq(k, input_key))
            .map(|_| ())
            .ok_or(AuthenticationError)
    }

    fn tls(&self) -> bool {
        self.tls
    }

    fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::SeqCst)
    }

    fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::SeqCst)
    }

    fn uses_dynamic_auth(&self) -> bool {
        self.oauth_command.is_some()
    }

    fn get_dynamic_auth_header(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref cmd) = self.oauth_command {
            let token = execute_oauth_command(cmd)?;
            Ok(format!("{}Bearer {}\r\n", http::HEADER_AUTHORIZATION, token))
        } else {
            Err("Not an OAuth provider".into())
        }
    }

    fn extra_headers(&self) -> Vec<&'static str> {
        if self.oauth_command.is_some() {
            vec![http::HEADER_ANTHROPIC_BETA]
        } else {
            vec![]
        }
    }

    fn transform_extra_header(&self, header_key: &str, existing_value: Option<&str>) -> Option<String> {
        // Only transform headers when using OAuth
        if self.oauth_command.is_none() {
            return None;
        }

        if header_key == http::HEADER_ANTHROPIC_BETA {
            const OAUTH_BETA_VALUE: &str = "oauth-2025-04-20";

            match existing_value {
                Some(existing) => {
                    // Check if oauth-2025-04-20 is already in the existing header
                    let values: Vec<&str> = existing.split(',').map(|s| s.trim()).collect();
                    if values.iter().any(|v| *v == OAUTH_BETA_VALUE) {
                        // Already contains the value, keep as is
                        Some(format!("{}{}\r\n", header_key, existing))
                    } else {
                        // Append the oauth beta value to existing header
                        Some(format!("{}{},{}\r\n", header_key, existing, OAUTH_BETA_VALUE))
                    }
                }
                None => {
                    // No existing header, add new one
                    Some(format!("{}{}\r\n", header_key, OAUTH_BETA_VALUE))
                }
            }
        } else {
            None
        }
    }

    #[allow(clippy::type_complexity)]
    fn health_check<'a: 'stream, 'stream>(
        &'a self,
        stream: &'stream mut dyn AsyncReadWrite,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + 'stream>>
    {
        if let Some(ref cfg) = self.health_check_config {
            Box::pin(health_check(
                stream,
                self.endpoint().as_bytes(),
                cfg.method.as_ref().map(|v| v.as_bytes()).unwrap_or(b"GET"),
                cfg.path.as_bytes(),
                self.auth_header().map(|v| v.as_bytes()),
                cfg.headers
                    .as_deref()
                    .map(|v| v.iter().map(|x| x.trim().as_bytes())),
                cfg.body.as_ref().map(|v| v.as_bytes()).unwrap_or_default(),
            ))
        } else {
            Box::pin(async move { Ok(()) })
        }
    }
}

fn replace_path<'a>(prefix: &str, block_str: &'a str) -> Cow<'a, str> {
    let path_range = http::get_req_path(block_str);
    let path = if path_range.start == path_range.end {
        "/"
    } else {
        &block_str[path_range.start..path_range.end]
    };

    let modified_path = if let Some(remaining) = path.strip_prefix(prefix) {
        if remaining.is_empty() {
            "/"
        } else {
            remaining
        }
    } else {
        return Cow::Borrowed(block_str);
    };

    // Build the result string
    let mut result = String::with_capacity(block_str.len());
    result.push_str(&block_str[..path_range.start]);
    result.push_str(modified_path);
    result.push_str(&block_str[path_range.end..]);
    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_path() {
        // Test basic prefix removal
        assert_eq!(
            replace_path("/v1", "GET /v1/completions HTTP/1.1"),
            "GET /completions HTTP/1.1"
        );

        // Test prefix removal with exact match
        assert_eq!(replace_path("/v1", "GET /v1 HTTP/1.1"), "GET / HTTP/1.1");

        // Test no prefix match
        assert_eq!(
            replace_path("/v1", "GET /api/users HTTP/1.1"),
            "GET /api/users HTTP/1.1"
        );

        // Test complex path with query parameters
        assert_eq!(
            replace_path("/v1", "GET /v1/completions?key=value HTTP/1.1"),
            "GET /completions?key=value HTTP/1.1"
        );

        // Test root path
        assert_eq!(replace_path("/", "GET / HTTP/1.1"), "GET / HTTP/1.1");

        // Test POST request
        assert_eq!(
            replace_path("/v1", "POST /v1/chat/completions HTTP/1.1"),
            "POST /chat/completions HTTP/1.1"
        );

        // Test with fragment
        assert_eq!(
            replace_path("/v1", "GET /v1/models#fragment HTTP/1.1"),
            "GET /models#fragment HTTP/1.1"
        );
    }

    #[test]
    fn test_constant_time_eq() {
        // Test equal strings
        assert!(constant_time_eq("hello", "hello"));
        assert!(constant_time_eq("", ""));
        assert!(constant_time_eq("a", "a"));

        // Test unequal strings
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hello!"));
        assert!(!constant_time_eq("hello", "hell"));
        assert!(!constant_time_eq("", "a"));

        // Test API key format strings
        assert!(constant_time_eq("sk-test-key-12345", "sk-test-key-12345"));
        assert!(!constant_time_eq("sk-test-key-12345", "sk-test-key-12346"));
    }

    #[test]
    fn test_type_display() {
        assert_eq!(Type::OpenAI.to_string(), "openai");
        assert_eq!(Type::Gemini.to_string(), "gemini");
        assert_eq!(Type::Anthropic.to_string(), "anthropic");
    }

    #[test]
    fn test_openai_provider_creation() {
        let auth_keys = Arc::new(vec!["test-auth-key".to_string()]);
        let provider = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("sk-test-key"),
            auth_keys,
            None,
            None,
        ).unwrap();

        assert!(matches!(provider.kind(), Type::OpenAI));
        assert_eq!(provider.host(), "api.openai.com");
        assert_eq!(provider.endpoint(), "api.openai.com");
        assert_eq!(provider.api_key(), Some("sk-test-key"));
        assert_eq!(provider.weight(), 1.0);
        assert!(provider.tls());
        assert!(provider.is_healthy());
        assert_eq!(provider.sock_address(), "api.openai.com:443");
        assert_eq!(provider.host_header(), "Host: api.openai.com\r\n");
        assert_eq!(provider.auth_header(), Some("Authorization: Bearer sk-test-key\r\n"));
        assert_eq!(provider.auth_header_key(), Some(http::HEADER_AUTHORIZATION));
        assert_eq!(provider.auth_query_key(), None);
    }

    #[test]
    fn test_openai_provider_without_tls() {
        let auth_keys = Arc::new(vec![]);
        let provider = OpenAIProvider::new(
            "localhost:8080",
            "localhost",
            Some(8080),
            false,
            2.0,
            Some("sk-test"),
            auth_keys,
            None,
            None,
        ).unwrap();

        assert!(!provider.tls());
        assert_eq!(provider.sock_address(), "localhost:8080");
        assert_eq!(provider.weight(), 2.0);
    }

    #[test]
    fn test_openai_provider_authentication() {
        let auth_keys = Arc::new(vec!["valid-key".to_string()]);
        let provider = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("sk-test"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // Test valid authentication
        let valid_header = "Authorization: Bearer valid-key";
        assert!(provider.authenticate(Some(valid_header.as_bytes())).is_ok());

        // Test invalid authentication
        let invalid_header = "Authorization: Bearer invalid-key";
        assert!(provider.authenticate(Some(invalid_header.as_bytes())).is_err());

        // Test missing authentication
        assert!(provider.authenticate(None).is_err());

        // Test authenticate_key directly
        assert!(provider.authenticate_key("valid-key").is_ok());
        assert!(provider.authenticate_key("Bearer valid-key").is_ok());
        assert!(provider.authenticate_key("invalid-key").is_err());
    }

    #[test]
    fn test_openai_provider_no_auth_keys() {
        let auth_keys = Arc::new(vec![]);
        let provider = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("sk-test"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // Without auth_keys, authentication should pass
        assert!(!provider.has_auth_keys());
        assert!(provider.authenticate(None).is_ok());
        assert!(provider.authenticate(Some(b"anything")).is_ok());
    }

    #[test]
    fn test_openai_provider_with_provider_auth_keys() {
        let auth_keys = Arc::new(vec![]);
        let provider_auth_keys = Some(vec!["provider-specific-key".to_string()]);
        let provider = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("sk-test"),
            auth_keys,
            provider_auth_keys,
            None,
        ).unwrap();

        assert!(provider.has_auth_keys());
        assert!(provider.authenticate_key("provider-specific-key").is_ok());
        assert!(provider.authenticate_key("wrong-key").is_err());
    }

    #[test]
    fn test_openai_provider_health_state() {
        let auth_keys = Arc::new(vec![]);
        let provider = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            None,
            auth_keys,
            None,
            None,
        ).unwrap();

        // Default is healthy
        assert!(provider.is_healthy());

        // Set to unhealthy
        provider.set_healthy(false);
        assert!(!provider.is_healthy());

        // Set back to healthy
        provider.set_healthy(true);
        assert!(provider.is_healthy());
    }

    #[test]
    fn test_gemini_provider_creation() {
        let auth_keys = Arc::new(vec!["test-auth-key".to_string()]);
        let provider = GeminiProvider::new(
            "generativelanguage.googleapis.com",
            "generativelanguage.googleapis.com",
            None,
            true,
            1.5,
            Some("gemini-api-key"),
            auth_keys,
            None,
            None,
        ).unwrap();

        assert!(matches!(provider.kind(), Type::Gemini));
        assert_eq!(provider.host(), "generativelanguage.googleapis.com");
        assert_eq!(provider.endpoint(), "generativelanguage.googleapis.com");
        assert_eq!(provider.api_key(), Some("gemini-api-key"));
        assert_eq!(provider.weight(), 1.5);
        assert_eq!(provider.auth_query_key(), Some(http::QUERY_KEY_KEY));
        assert_eq!(provider.auth_header_key(), Some(http::HEADER_X_GOOG_API_KEY));
    }

    #[test]
    fn test_gemini_provider_requires_api_key() {
        let auth_keys = Arc::new(vec![]);
        let result = GeminiProvider::new(
            "generativelanguage.googleapis.com",
            "generativelanguage.googleapis.com",
            None,
            true,
            1.0,
            None, // Missing API key
            auth_keys,
            None,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_gemini_provider_authentication() {
        let auth_keys = Arc::new(vec!["client-key".to_string()]);
        let provider = GeminiProvider::new(
            "generativelanguage.googleapis.com",
            "generativelanguage.googleapis.com",
            None,
            true,
            1.0,
            Some("gemini-api-key"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // Test with x-goog-api-key header
        let valid_header = "x-goog-api-key: client-key";
        assert!(provider.authenticate(Some(valid_header.as_bytes())).is_ok());

        // Test without header prefix
        assert!(provider.authenticate(Some(b"client-key")).is_ok());

        // Test invalid key
        assert!(provider.authenticate(Some(b"wrong-key")).is_err());
    }

    #[test]
    fn test_anthropic_provider_creation() {
        let auth_keys = Arc::new(vec!["test-auth-key".to_string()]);
        let provider = AnthropicProvider::new(
            "api.anthropic.com",
            "api.anthropic.com",
            None,
            true,
            0.5,
            Some("anthropic-api-key"),
            auth_keys,
            None,
            None,
        ).unwrap();

        assert!(matches!(provider.kind(), Type::Anthropic));
        assert_eq!(provider.host(), "api.anthropic.com");
        assert_eq!(provider.endpoint(), "api.anthropic.com");
        assert_eq!(provider.api_key(), Some("anthropic-api-key"));
        assert_eq!(provider.weight(), 0.5);
        assert_eq!(provider.auth_header_key(), Some(http::HEADER_X_API_KEY));
        assert_eq!(provider.auth_query_key(), None);
    }

    #[test]
    fn test_anthropic_provider_requires_api_key() {
        let auth_keys = Arc::new(vec![]);
        let result = AnthropicProvider::new(
            "api.anthropic.com",
            "api.anthropic.com",
            None,
            true,
            1.0,
            None, // Missing API key
            auth_keys,
            None,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_anthropic_provider_authentication() {
        let auth_keys = Arc::new(vec!["client-key".to_string()]);
        let provider = AnthropicProvider::new(
            "api.anthropic.com",
            "api.anthropic.com",
            None,
            true,
            1.0,
            Some("anthropic-api-key"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // Test with X-API-Key header
        let valid_header = "X-API-Key: client-key";
        assert!(provider.authenticate(Some(valid_header.as_bytes())).is_ok());

        // Test invalid header key
        let wrong_header = "Authorization: Bearer client-key";
        assert!(provider.authenticate(Some(wrong_header.as_bytes())).is_err());
    }

    #[test]
    fn test_new_provider_factory() {
        let auth_keys = Arc::new(vec![]);

        // Test OpenAI
        let openai = new_provider(
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
        ).unwrap();
        assert!(matches!(openai.kind(), Type::OpenAI));

        // Test Gemini
        let gemini = new_provider(
            "gemini",
            "generativelanguage.googleapis.com",
            "generativelanguage.googleapis.com",
            None,
            true,
            1.0,
            Some("gemini-key"),
            Arc::clone(&auth_keys),
            None,
            None,
        ).unwrap();
        assert!(matches!(gemini.kind(), Type::Gemini));

        // Test Anthropic
        let anthropic = new_provider(
            "anthropic",
            "api.anthropic.com",
            "api.anthropic.com",
            None,
            true,
            1.0,
            Some("anthropic-key"),
            Arc::clone(&auth_keys),
            None,
            None,
        ).unwrap();
        assert!(matches!(anthropic.kind(), Type::Anthropic));

        // Test unsupported provider
        let unsupported = new_provider(
            "unknown",
            "example.com",
            "example.com",
            None,
            true,
            1.0,
            Some("key"),
            Arc::clone(&auth_keys),
            None,
            None,
        );
        assert!(unsupported.is_err());
    }

    #[test]
    fn test_provider_default_ports() {
        let auth_keys = Arc::new(vec![]);

        // TLS enabled should default to port 443
        let provider_tls = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("key"),
            Arc::clone(&auth_keys),
            None,
            None,
        ).unwrap();
        assert_eq!(provider_tls.sock_address(), "api.openai.com:443");

        // TLS disabled should default to port 80
        let provider_no_tls = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            false,
            1.0,
            Some("key"),
            Arc::clone(&auth_keys),
            None,
            None,
        ).unwrap();
        assert_eq!(provider_no_tls.sock_address(), "api.openai.com:80");

        // Custom port should override defaults
        let provider_custom = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            Some(8443),
            true,
            1.0,
            Some("key"),
            Arc::clone(&auth_keys),
            None,
            None,
        ).unwrap();
        assert_eq!(provider_custom.sock_address(), "api.openai.com:8443");
    }

    #[test]
    fn test_openai_provider_without_api_key() {
        let auth_keys = Arc::new(vec![]);
        let provider = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            None, // No API key
            auth_keys,
            None,
            None,
        ).unwrap();

        assert_eq!(provider.api_key(), None);
        assert_eq!(provider.auth_header(), None);
    }

    #[test]
    fn test_rewrite_first_header_block() {
        let auth_keys = Arc::new(vec![]);

        // Provider with path prefix
        let provider = OpenAIProvider::new(
            "localhost/v1",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("key"),
            auth_keys.clone(),
            None,
            None,
        ).unwrap();

        let block = b"GET /v1/completions HTTP/1.1";
        let rewritten = provider.rewrite_first_header_block(block);
        assert!(rewritten.is_some());
        assert_eq!(String::from_utf8(rewritten.unwrap()).unwrap(), "GET /completions HTTP/1.1");

        // Provider without path prefix
        let provider_no_prefix = OpenAIProvider::new(
            "localhost",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("key"),
            auth_keys,
            None,
            None,
        ).unwrap();

        let rewritten = provider_no_prefix.rewrite_first_header_block(block);
        assert!(rewritten.is_none());
    }

    #[test]
    fn test_gemini_rewrite_with_query_key() {
        let auth_keys = Arc::new(vec![]);
        let provider = GeminiProvider::new(
            "localhost/v1beta",
            "generativelanguage.googleapis.com",
            None,
            true,
            1.0,
            Some("gemini-api-key"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // Test rewriting path and query key
        let block = b"GET /v1beta/models?key=client-key HTTP/1.1";
        let rewritten = provider.rewrite_first_header_block(block);
        assert!(rewritten.is_some());
        let result = String::from_utf8(rewritten.unwrap()).unwrap();
        assert!(result.contains("key=gemini-api-key"));
        assert!(result.starts_with("GET /models?"));
    }

    #[test]
    fn test_authentication_error_display() {
        let error = AuthenticationError;
        assert_eq!(format!("{}", error), "Authentication error");
    }

    #[test]
    fn test_multiple_auth_keys() {
        let auth_keys = Arc::new(vec![
            "key1".to_string(),
            "key2".to_string(),
            "key3".to_string(),
        ]);
        let provider = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("sk-test"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // All keys should work
        assert!(provider.authenticate_key("key1").is_ok());
        assert!(provider.authenticate_key("key2").is_ok());
        assert!(provider.authenticate_key("key3").is_ok());
        assert!(provider.authenticate_key("key4").is_err());
    }

    #[test]
    fn test_authentication_key_trimming() {
        let auth_keys = Arc::new(vec!["valid-key".to_string()]);
        let provider = OpenAIProvider::new(
            "api.openai.com",
            "api.openai.com",
            None,
            true,
            1.0,
            Some("sk-test"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // OpenAI strips "Bearer " prefix
        assert!(provider.authenticate_key("Bearer valid-key").is_ok());
        assert!(provider.authenticate_key("  valid-key  ").is_ok());

        // Anthropic provider
        let anthropic_provider = AnthropicProvider::new(
            "api.anthropic.com",
            "api.anthropic.com",
            None,
            true,
            1.0,
            Some("key"),
            Arc::new(vec!["valid-key".to_string()]),
            None,
            None,
        ).unwrap();

        // Anthropic trims whitespace
        assert!(anthropic_provider.authenticate_key("  valid-key  ").is_ok());
    }

    #[test]
    fn test_is_oauth_command() {
        assert!(is_oauth_command("$(echo test)"));
        assert!(is_oauth_command("$(cat .credentials.json | jq .token)"));
        assert!(is_oauth_command("$()"));

        assert!(!is_oauth_command("sk-12345"));
        assert!(!is_oauth_command("$(incomplete"));
        assert!(!is_oauth_command("incomplete)"));
        assert!(!is_oauth_command("$incomplete"));
        assert!(!is_oauth_command(""));
    }

    #[test]
    fn test_extract_oauth_command() {
        assert_eq!(extract_oauth_command("$(echo test)"), Some("echo test"));
        assert_eq!(
            extract_oauth_command("$(cat .credentials.json | jq .token)"),
            Some("cat .credentials.json | jq .token")
        );
        assert_eq!(extract_oauth_command("$()"), Some(""));

        assert_eq!(extract_oauth_command("sk-12345"), None);
        assert_eq!(extract_oauth_command("$(incomplete"), None);
    }

    #[test]
    fn test_execute_oauth_command() {
        // Test successful command
        let result = execute_oauth_command("echo test-token");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-token");

        // Test command with whitespace trimming
        let result = execute_oauth_command("echo '  token  '");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "token");

        // Test failing command
        let result = execute_oauth_command("exit 1");
        assert!(result.is_err());
    }

    #[test]
    fn test_anthropic_provider_oauth_mode() {
        let auth_keys = Arc::new(vec![]);
        let provider = AnthropicProvider::new(
            "api.anthropic.com",
            "api.anthropic.com",
            None,
            true,
            1.0,
            Some("$(echo oauth-token-123)"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // Should be in OAuth mode
        assert!(provider.uses_oauth());
        assert!(provider.auth_header().is_none()); // Static auth header should be None

        // Should return dynamic auth header
        let dynamic_auth = provider.get_dynamic_auth_header();
        assert!(dynamic_auth.is_ok());
        assert_eq!(dynamic_auth.unwrap(), "Authorization: Bearer oauth-token-123\r\n");
    }

    #[test]
    fn test_anthropic_provider_standard_mode() {
        let auth_keys = Arc::new(vec![]);
        let provider = AnthropicProvider::new(
            "api.anthropic.com",
            "api.anthropic.com",
            None,
            true,
            1.0,
            Some("sk-ant-api-key-123"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // Should NOT be in OAuth mode
        assert!(!provider.uses_oauth());
        assert_eq!(provider.auth_header(), Some("X-API-Key: sk-ant-api-key-123\r\n"));

        // Dynamic auth should fail
        let dynamic_auth = provider.get_dynamic_auth_header();
        assert!(dynamic_auth.is_err());
    }

    #[test]
    fn test_anthropic_provider_oauth_extra_headers() {
        let auth_keys = Arc::new(vec![]);
        let provider = AnthropicProvider::new(
            "api.anthropic.com",
            "api.anthropic.com",
            None,
            true,
            1.0,
            Some("$(echo token)"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // Should have anthropic-beta in extra headers
        let extra = provider.extra_headers();
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0], http::HEADER_ANTHROPIC_BETA);

        // Without existing anthropic-beta header
        let result = provider.transform_extra_header(http::HEADER_ANTHROPIC_BETA, None);
        assert_eq!(result, Some("anthropic-beta: oauth-2025-04-20\r\n".to_string()));

        // With existing anthropic-beta header (without oauth value)
        let result = provider.transform_extra_header(http::HEADER_ANTHROPIC_BETA, Some("streaming-2024-01-01"));
        assert_eq!(result, Some("anthropic-beta: streaming-2024-01-01,oauth-2025-04-20\r\n".to_string()));

        // With existing anthropic-beta header (already contains oauth value)
        let result = provider.transform_extra_header(http::HEADER_ANTHROPIC_BETA, Some("oauth-2025-04-20"));
        assert_eq!(result, Some("anthropic-beta: oauth-2025-04-20\r\n".to_string()));

        // With existing anthropic-beta header (already contains oauth value among others)
        let result = provider.transform_extra_header(http::HEADER_ANTHROPIC_BETA, Some("streaming-2024-01-01, oauth-2025-04-20"));
        assert_eq!(result, Some("anthropic-beta: streaming-2024-01-01, oauth-2025-04-20\r\n".to_string()));
    }

    #[test]
    fn test_anthropic_provider_standard_no_extra_headers() {
        let auth_keys = Arc::new(vec![]);
        let provider = AnthropicProvider::new(
            "api.anthropic.com",
            "api.anthropic.com",
            None,
            true,
            1.0,
            Some("sk-ant-api-key-123"),
            auth_keys,
            None,
            None,
        ).unwrap();

        // Standard mode should not have any extra headers
        let extra = provider.extra_headers();
        assert!(extra.is_empty());

        // transform_extra_header should return None
        let result = provider.transform_extra_header(http::HEADER_ANTHROPIC_BETA, None);
        assert!(result.is_none());

        let result = provider.transform_extra_header(http::HEADER_ANTHROPIC_BETA, Some("streaming-2024-01-01"));
        assert!(result.is_none());
    }
}

async fn health_check(
    stream: &mut dyn AsyncReadWrite,
    endpoint: &[u8],
    method: &[u8],
    path: &[u8],
    authorization: Option<&[u8]>,
    headers: Option<impl Iterator<Item=&[u8]>>,
    req: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_all(method).await?;
    stream.write_all(b" ").await?;
    stream.write_all(path).await?;
    stream.write_all(b" HTTP/1.1\r\n").await?;
    stream.write_all(b"Host: ").await?;
    stream.write_all(endpoint).await?;
    stream.write_all(b"\r\n").await?;
    stream.write_all(b"Connection: keep-alive\r\n").await?;
    stream.write_all(b"Content-Length: ").await?;
    stream.write_all(req.len().to_string().as_bytes()).await?;
    stream.write_all(b"\r\n").await?;
    if let Some(authorization) = authorization {
        stream.write_all(authorization).await?;
    }
    if let Some(headers) = headers {
        for header in headers {
            stream.write_all(header).await?;
            stream.write_all(b"\r\n").await?;
        }
    }
    stream.write_all(b"\r\n").await?;
    stream.write_all(req).await?;
    let response = http::Response::new(stream).await?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parser = httparse::Response::new(&mut headers);
    parser.parse(response.payload.block())?;
    let Some(http_status_code) = parser.code else {
        return Err("unknown http status code".into());
    };
    if http_status_code / 100 != 2 {
        return Err(format!("invalid http status code: {}", http_status_code).into());
    }
    Ok(())
}
