use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam::deque::{Injector, Steal};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::provider::AsyncReadWrite;
use crate::worker::{PoolTrait, ProxyError, WorkerTrait};

pub struct Executor<P> {
    conn_injector: Arc<P>,
}

impl<P: PoolTrait> Executor<P> {
    pub fn new(pool: P) -> Self {
        Executor {
            conn_injector: Arc::new(pool),
        }
    }

    pub fn run_health_check<W: WorkerTrait<P>>(&self)
    where
        W: Send + 'static,
        <P as PoolTrait>::Item: AsyncReadWrite + 'static,
    {
        let mut worker = W::new(Arc::clone(&self.conn_injector));
        tokio::spawn(async move {
            loop {
                let p = crate::program();
                let providers = p.read().await.providers.clone();
                for provider in providers.iter() {
                    let provider_api_key = || {
                        provider
                            .api_key()
                            .map(|k| {
                                if let (Some(prefix), Some(suffix)) =
                                    (k.get(..3), k.get(k.len() - 4..))
                                {
                                    Some(format!("{}...{}", prefix, suffix))
                                } else {
                                    None
                                }
                            })
                            .flatten()
                    };
                    let fut = async {
                        let Ok(mut conn) = worker.get_outgoing_conn(&**provider).await else {
                            provider.set_healthy(false);
                            return;
                        };
                        if let Err(e) = provider.health_check(&mut conn).await {
                            if provider.is_healthy() {
                                log::warn!(provider = provider.host(), api_key = provider_api_key(), error = e.to_string(); "health_check_error");
                            }
                            provider.set_healthy(false);
                        } else {
                            if !provider.is_healthy() {
                                log::info!(provider = provider.host(), api_key = provider_api_key(); "provider_re_enable");
                            }
                            provider.set_healthy(true);
                        }
                        worker.add(provider.endpoint(), conn).await;
                    };
                    if tokio::time::timeout(Duration::from_secs(30), fut)
                        .await
                        .is_err()
                    {
                        log::warn!(provider = provider.host(), api_key = provider_api_key(); "health_check_timeout");
                        provider.set_healthy(false);
                    }
                }
                let health_check_interval = p.read().await.health_check_interval;
                tokio::time::sleep(Duration::from_secs(health_check_interval)).await;
            }
        });
    }

    pub async fn execute<W: WorkerTrait<P>>(&self, stream: TcpStream)
    where
        <P as PoolTrait>::Item: Unpin + Send + Sync + 'static,
    {
        let p = crate::program();
        let (tls_server_config, mut shutdown_rx) = {
            let guard = p.read().await;
            (guard.tls_server_config.clone(), guard.shutdown_tx.subscribe())
        };
        let Some(tls_server_config) = tls_server_config else {
            log::error!("TLS server config not available for HTTPS connection");
            return;
        };
        let conn_injector = Arc::clone(&self.conn_injector);
        tokio::select! {
            _ = shutdown_rx.recv() => {}
            _ = async move {
                let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_server_config);
                let mut tls_stream = match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => tls_stream,
                    #[cfg_attr(not(debug_assertions), allow(unused))]
                    Err(e) => {
                        #[cfg(debug_assertions)]
                        log::error!(error = e.to_string(); "tls_accept_error");
                        return;
                    }
                };
                let mut worker = W::new(conn_injector);
                let alpn = tls_stream.get_ref().1.alpn_protocol();
                #[cfg(debug_assertions)]
                log::info!(alpn = alpn.map(|v| String::from_utf8_lossy(v)); "alpn_protocol");
                if matches!(alpn, Some(b"h2")) {
                    #[cfg_attr(not(debug_assertions), allow(unused))]
                    if let Err(e) = worker.proxy_h2(&mut tls_stream).await {
                        #[cfg(debug_assertions)]
                        log::error!(alpn = "h2", error = e.to_string(); "proxy_h2_error");
                    }
                } else {
                    match worker.proxy(&mut tls_stream).await {
                        Err(ProxyError::Abort(e)) => {
                            if cfg!(debug_assertions)
                                || !matches!(&e, crate::Error::IO(io_error) if io_error.kind() == io::ErrorKind::BrokenPipe)
                            {
                                log::error!(alpn = "http/1.1", error = e.to_string(); "proxy_abort_error");
                            }
                        }
                        #[cfg(debug_assertions)]
                        Err(ProxyError::Client(e)) => {
                            log::warn!(alpn = "http/1.1", error = e.to_string(); "proxy_client_error");
                        }
                        Err(ProxyError::Server(e)) => {
                            log::error!(alpn = "http/1.1", error = e.to_string(); "proxy_server_error");
                            #[allow(unused)]
                            {
                                let body = format!("upstream: {}", e.to_string());
                                let resp = format!(
                                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.as_bytes().len(),
                                    body
                                );
                                tls_stream.write_all(resp.as_bytes()).await;
                            }
                        }
                        _ => (),
                    }
                }
                #[allow(unused)]
                tls_stream.flush().await;
                #[allow(unused)]
                tls_stream.shutdown().await;
            } => {}
        }
    }

    /// Execute HTTP (plaintext) connection - HTTP/1.1 only, no HTTP/2 support
    pub async fn execute_http<W: WorkerTrait<P>>(&self, mut stream: TcpStream)
    where
        <P as PoolTrait>::Item: Unpin + Send + Sync + 'static,
    {
        let p = crate::program();
        let mut shutdown_rx = p.read().await.shutdown_tx.subscribe();
        let conn_injector = Arc::clone(&self.conn_injector);
        tokio::select! {
            _ = shutdown_rx.recv() => {}
            _ = async {
                let mut worker = W::new(conn_injector);
                #[cfg(debug_assertions)]
                log::info!(protocol = "http/1.1"; "http_connection");
                match worker.proxy(&mut stream).await {
                    Err(ProxyError::Abort(e)) => {
                        if cfg!(debug_assertions)
                            || !matches!(&e, crate::Error::IO(io_error) if io_error.kind() == io::ErrorKind::BrokenPipe)
                        {
                            log::error!(protocol = "http/1.1", error = e.to_string(); "proxy_abort_error");
                        }
                    }
                    #[cfg(debug_assertions)]
                    Err(ProxyError::Client(e)) => {
                        log::warn!(protocol = "http/1.1", error = e.to_string(); "proxy_client_error");
                    }
                    Err(ProxyError::Server(e)) => {
                        log::error!(protocol = "http/1.1", error = e.to_string(); "proxy_server_error");
                        #[allow(unused)]
                        {
                            let body = format!("upstream: {}", e.to_string());
                            let resp = format!(
                                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.as_bytes().len(),
                                body
                            );
                            stream.write_all(resp.as_bytes()).await;
                        }
                    }
                    _ => (),
                }
                #[allow(unused)]
                stream.flush().await;
                #[allow(unused)]
                stream.shutdown().await;
            } => {}
        }
    }
}

/// Default maximum connections per endpoint to prevent resource exhaustion DoS
const DEFAULT_MAX_CONNECTIONS_PER_ENDPOINT: usize = 100;

pub struct Pool<T> {
    injectors: RwLock<BTreeMap<String, Injector<T>>>,
    /// Track connection count per endpoint
    conn_counts: RwLock<BTreeMap<String, Arc<AtomicUsize>>>,
    /// Maximum connections allowed per endpoint
    max_connections_per_endpoint: usize,
}

impl<T> Pool<T> {
    pub fn new() -> Self {
        Self::with_max_connections(DEFAULT_MAX_CONNECTIONS_PER_ENDPOINT)
    }

    pub fn with_max_connections(max_connections_per_endpoint: usize) -> Self {
        Pool {
            injectors: RwLock::new(BTreeMap::new()),
            conn_counts: RwLock::new(BTreeMap::new()),
            max_connections_per_endpoint,
        }
    }
}

impl<T> PoolTrait for Pool<T> {
    type Item = T;

    fn get<'a, L>(&'a self, label: &'a L) -> Pin<Box<dyn Future<Output=Option<T>> + Send + 'a>>
    where
        String: Borrow<L>,
        T: Send,
        L: Ord + Sync + ?Sized,
    {
        Box::pin(async move {
            let result = self.injectors
                .read()
                .await
                .get(label)
                .and_then(|injector| {
                    if let Steal::Success(v) = injector.steal() {
                        Some(v)
                    } else {
                        None
                    }
                });
            // Decrement connection count when taking from pool
            if result.is_some() {
                if let Some(count) = self.conn_counts.read().await.get(label) {
                    count.fetch_sub(1, Ordering::SeqCst);
                }
            }
            result
        })
    }

    fn add<'a, L>(&'a self, label: &'a L, value: T) -> Pin<Box<dyn Future<Output=()> + Send + 'a>>
    where
        String: Borrow<L>,
        T: Send,
        L: ToString + Sync + Ord + ?Sized,
    {
        Box::pin(async move {
            // Initialize data structures if needed
            if !self.injectors.read().await.contains_key(label) {
                let mut injectors = self.injectors.write().await;
                let mut conn_counts = self.conn_counts.write().await;
                if !injectors.contains_key(label) {
                    injectors.insert(label.to_string(), Injector::new());
                    conn_counts.insert(label.to_string(), Arc::new(AtomicUsize::new(0)));
                }
            }

            // Check if we're at capacity before adding
            let current_count = self.conn_counts
                .read()
                .await
                .get(label)
                .map(|c| c.load(Ordering::SeqCst))
                .unwrap_or(0);

            if current_count >= self.max_connections_per_endpoint {
                // Pool is full, drop the connection instead of adding it
                // The connection will be dropped when `value` goes out of scope
                log::warn!(
                    endpoint = label.to_string(),
                    current = current_count,
                    max = self.max_connections_per_endpoint;
                    "connection_pool_full"
                );
                return;
            }

            // Add to pool and increment count
            if let Some(injector) = self.injectors.read().await.get(label) {
                injector.push(value);
                if let Some(count) = self.conn_counts.read().await.get(label) {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
    }
}
