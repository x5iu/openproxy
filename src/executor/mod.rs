use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
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
        let tls_server_config = p.read().await.tls_server_config.clone();
        let tls_acceptor =
            tokio_rustls::TlsAcceptor::from(tls_server_config);
        let mut tls_stream = match tls_acceptor.accept(stream).await {
            Ok(tls_stream) => tls_stream,
            #[cfg_attr(not(debug_assertions), allow(unused))]
            Err(e) => {
                #[cfg(debug_assertions)]
                log::error!(error = e.to_string(); "tls_accept_error");
                return;
            }
        };
        let mut worker = W::new(Arc::clone(&self.conn_injector));
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
    }
}

pub struct Pool<T> {
    injectors: RwLock<BTreeMap<String, Injector<T>>>,
}

impl<T> Pool<T> {
    pub fn new() -> Self {
        Pool {
            injectors: RwLock::new(BTreeMap::new()),
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
            self.injectors
                .read()
                .await
                .get(label)
                .map(|injector| {
                    if let Steal::Success(v) = injector.steal() {
                        Some(v)
                    } else {
                        None
                    }
                })
                .flatten()
        })
    }

    fn add<'a, L>(&'a self, label: &'a L, value: T) -> Pin<Box<dyn Future<Output=()> + Send + 'a>>
    where
        String: Borrow<L>,
        T: Send,
        L: ToString + Sync + Ord + ?Sized,
    {
        Box::pin(async move {
            if !self.injectors.read().await.contains_key(label) {
                let mut injectors = self.injectors.write().await;
                if !injectors.contains_key(label) {
                    injectors.insert(label.to_string(), Injector::new());
                }
            }
            self.injectors
                .read()
                .await
                .get(label)
                .map(|injector| injector.push(value));
        })
    }
}
