use std::borrow::{Borrow, Cow};
use std::future::Future;
use std::io::Cursor;
use std::mem;
use std::pin::{pin, Pin};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;


use bytes::Buf;

use crate::http;
use crate::provider::Provider;
use crate::Error;

static TLS_CLIENT_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
});

type TlsIncomingStream = tokio_rustls::server::TlsStream<TcpStream>;
type TlsOutgoingStream = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Client error: {0}")]
    Client(Error),
    #[error("Server error: {0}")]
    Server(Error),
    #[error("Abort: {0}")]
    Abort(Error),
}

pub trait WorkerTrait<P>
where
    P: PoolTrait,
{
    fn new(injector: Arc<P>) -> Self;
    fn get_outgoing_conn<'a>(
        &'a mut self,
        provider: &'a dyn Provider,
    ) -> Pin<Box<dyn Future<Output=Result<<P as PoolTrait>::Item, Error>> + Send + 'a>>
    where
        <P as PoolTrait>::Item: Send;
    fn proxy<'a, S>(
        &'a mut self,
        incoming: &'a mut S,
    ) -> Pin<Box<dyn Future<Output=Result<(), ProxyError>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
        <P as PoolTrait>::Item: Unpin + Send + Sync;
    fn proxy_h2<'a>(
        &'a mut self,
        incoming: &'a mut TlsIncomingStream,
    ) -> Pin<Box<dyn Future<Output=Result<(), ProxyError>> + Send + 'a>>
    where
        <P as PoolTrait>::Item: Unpin + Send + Sync + 'static;
    fn add<'a>(
        &'a mut self,
        endpoint: &'a str,
        conn: <P as PoolTrait>::Item,
    ) -> Pin<Box<dyn Future<Output=()> + Send + 'a>> where
        <P as PoolTrait>::Item: Send;
}

pub struct Worker<P> {
    pool: Arc<P>,
}

impl<P> WorkerTrait<P> for Worker<P>
where
    P: PoolTrait + Send + Sync + 'static,
    <P as PoolTrait>::Item: ConnTrait,
{
    fn new(pool: Arc<P>) -> Self {
        Self { pool }
    }

    fn get_outgoing_conn<'a>(
        &'a mut self,
        provider: &'a dyn Provider,
    ) -> Pin<Box<dyn Future<Output=Result<<P as PoolTrait>::Item, Error>> + Send + 'a>>
    where
        <P as PoolTrait>::Item: Send,
    {
        Box::pin(async move {
            if let Some(conn) = self.select(provider.endpoint()).await {
                Ok(conn)
            } else {
                let stream = TcpStream::connect(provider.sock_address()).await?;
                let conn = if provider.tls() {
                    let connector = new_tls_connector();
                    <P as PoolTrait>::Item::new_tls(provider.endpoint(), stream, connector).await?
                } else {
                    <P as PoolTrait>::Item::new(provider.endpoint(), stream)
                };
                Ok(conn)
            }
        })
    }

    fn proxy<'a, S>(
        &'a mut self,
        mut incoming: &'a mut S,
    ) -> Pin<Box<dyn Future<Output=Result<(), ProxyError>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
        <P as PoolTrait>::Item: Unpin + Send + Sync,
    {
        Box::pin(async move {
            let mut is_invalid_key = false;
            let mut is_bad_request = false;
            let mut err_msg: Option<Cow<str>> = None;
            loop {
                let mut request = match http::Request::new(&mut incoming).await {
                    Ok(request) => request,
                    Err(Error::HeaderTooLarge) => {
                        is_bad_request = true;
                        err_msg = Some("header too large".into());
                        break;
                    }
                    Err(Error::InvalidHeader) => {
                        is_bad_request = true;
                        err_msg = Some("invalid header".into());
                        break;
                    }
                    Err(e) => return Err(ProxyError::Client(e)),
                };
                let p = crate::program();
                let Some(host) = request.host() else {
                    is_bad_request = true;
                    err_msg = Some("missing Host header".into());
                    break;
                };
                let p = p.read().await;
                let Some(provider) = p.select_provider(host, request.path()) else {
                    is_bad_request = true;
                    err_msg = Some("no provider matched".into());
                    break;
                };
                if !provider.authenticate(request.auth_key()).is_ok() {
                    #[cfg(debug_assertions)]
                    log::error!(provider = provider.kind().to_string(), header:serde = request.auth_key().map(|header| header.to_vec()); "authentication_failed");
                    is_invalid_key = true;
                    err_msg = Some("authentication failed".into());
                    break;
                }
                let mut outgoing = self
                    .get_outgoing_conn(provider)
                    .await
                    .map_err(ProxyError::Server)?;
                request
                    .write_to(&mut outgoing)
                    .await
                    .map_err(ProxyError::Server)?;
                let incoming_conn_keep_alive = request.payload.conn_keep_alive;
                drop(request);
                let mut response = http::Response::new(&mut outgoing)
                    .await
                    .map_err(ProxyError::Abort)?;
                response
                    .write_to(&mut incoming)
                    .await
                    .map_err(ProxyError::Abort)?;
                let conn_keep_alive = response.payload.conn_keep_alive;
                drop(response);
                if conn_keep_alive {
                    self.add(provider.endpoint(), outgoing).await;
                }
                if !incoming_conn_keep_alive {
                    break;
                }
            }
            if is_invalid_key {
                let msg = err_msg.as_deref().unwrap_or("authentication failed");
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    msg.as_bytes().len(),
                    msg
                );
                incoming
                    .write_all(resp.as_bytes())
                    .await
                    .map_err(|e| ProxyError::Client(e.into()))?;
            } else if is_bad_request {
                let msg = err_msg.as_deref().unwrap_or("bad request");
                let resp = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    msg.as_bytes().len(),
                    msg
                );
                incoming
                    .write_all(resp.as_bytes())
                    .await
                    .map_err(|e| ProxyError::Client(e.into()))?;
            }
            Ok(())
        })
    }

    fn proxy_h2<'a>(
        &'a mut self,
        incoming: &'a mut TlsIncomingStream,
    ) -> Pin<Box<dyn Future<Output=Result<(), ProxyError>> + Send + 'a>>
    where
        <P as PoolTrait>::Item: Unpin + Send + Sync + 'static,
    {
        macro_rules! invalid {
            ($respond:expr, $status:expr, $msg:expr) => {{
                let msg: Cow<str> = $msg.into();
                let body_bytes = msg.as_bytes();
                let body: Vec<u8> = Vec::from(body_bytes);
                let builder = httplib::Response::builder()
                    .version(httplib::Version::HTTP_2)
                    .status($status)
                    .header("content-type", "text/plain; charset=utf-8");
                let mut send = match $respond.send_response(builder.body(()).unwrap(), false) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!(alpn = "h2", error = e.to_string(); "send_response_error");
                        return;
                    }
                };
                if let Err(e) = send.send_data(bytes::Bytes::from(body), true) {
                    log::error!(alpn = "h2", error = e.to_string(); "send_data_error");
                    return;
                }
                ()
            }};
        }
        Box::pin(async move {
            let mut stream = h2::server::handshake(incoming)
                .await
                .map_err(|e| ProxyError::Client(e.into()))?;
            while let Some(next) = stream.accept().await {
                let (mut request, mut respond) = next.map_err(|e| ProxyError::Client(e.into()))?;
                let mut worker = Worker::new(self.pool.clone());
                tokio::spawn(async move {
                    let p = crate::program();
                    let Some(authority) = request.uri().authority() else {
                        return invalid!(respond, 400, "missing :authority");
                    };
                    let p = p.read().await;
                    let Some(provider) = p.select_provider(authority.host(), request.uri().path()) else {
                        return invalid!(respond, 400, "no provider matched");
                    };
                    if provider.has_auth_keys() {
                        let mut auth_key = None;
                        if let Some(auth_header_key) = provider.auth_header_key() {
                            auth_key = request
                                .headers()
                                .get(auth_header_key.trim_end_matches(|ch| ch == ' ' || ch == ':'))
                                .map(|v| v.to_str().ok())
                                .flatten();
                        }
                        if auth_key.is_none() {
                            if let Some(auth_query_key) = provider.auth_query_key() {
                                auth_key = request
                                    .uri()
                                    .query()
                                    .map(|query| {
                                        http::get_auth_query_range(query, auth_query_key)
                                            .map(|range| &query[range])
                                    })
                                    .flatten()
                            }
                        }
                        let Some(auth_key) = auth_key else {
                            return invalid!(respond, 401, "missing authentication");
                        };
                        if !provider.authenticate_key(auth_key).is_ok() {
                            return invalid!(respond, 401, "authentication failed");
                        }
                    }
                    let host = authority.host().to_string();
                    request
                        .headers_mut()
                        .entry("Connection")
                        .or_insert(httplib::HeaderValue::from_static("keep-alive"));
                    request
                        .headers_mut()
                        .entry("Host")
                        .or_insert(httplib::HeaderValue::from_str(&host).unwrap());
                    let mut req_headers = String::with_capacity(1024);
                    for (key, value) in request.headers() {
                        req_headers.push_str(key.as_str());
                        req_headers.push_str(": ");
                        req_headers.push_str(String::from_utf8_lossy(value.as_bytes()).as_ref());
                        req_headers.push_str("\r\n");
                    }
                    let has_content_length = request.headers().contains_key("content-length");
                    if !has_content_length {
                        req_headers.push_str("Transfer-Encoding: chunked\r\n");
                    }
                    let req_str = format!(
                        "{} {} HTTP/1.1\r\n{}\r\n",
                        request.method(),
                        request
                            .uri()
                            .path_and_query()
                            .map(|pq| pq.as_str())
                            .unwrap_or("/"),
                        req_headers,
                    );
                    let h2_stream_reader = H2StreamReader::new(request.into_body());
                    let req_body: Box<dyn AsyncRead + Unpin + Send + Sync> = if has_content_length {
                        Box::new(h2_stream_reader)
                    } else {
                        Box::new(http::reader::ChunkedWriter::new(h2_stream_reader))
                    };
                    let req_reader = AsyncReadExt::chain(req_str.as_bytes(), req_body);
                    let mut req = match http::Request::new(req_reader).await {
                        Ok(req) => req,
                        Err(e) => { return invalid!(respond, 400, e.to_string()); }
                    };
                    let mut outgoing = match worker.get_outgoing_conn(provider).await {
                        Ok(conn) => conn,
                        Err(e) => { return invalid!(respond, 502, format!("upstream: {}", e.to_string())); }
                    };
                    if let Err(e) = req.write_to(&mut outgoing).await {
                        return invalid!(respond, 502, format!("upstream: {}", e.to_string()));
                    };
                    let mut response = match http::Response::new(&mut outgoing).await {
                        Ok(resp) => resp,
                        Err(e) => { return invalid!(respond, 502, format!("upstream: {}", e.to_string())); }
                    };
                    let mut headers = [httparse::EMPTY_HEADER; 64];
                    let mut parser = httparse::Response::new(&mut headers);
                    if let Err(e) = parser.parse(response.payload.block()) {
                        return invalid!(respond, 502, format!("upstream: {}", e.to_string()));
                    };
                    let mut builder = httplib::Response::builder()
                        .version(httplib::Version::HTTP_2)
                        .status(parser.code.unwrap_or(502));
                    let mut is_transfer_encoding_chunked = false;
                    for header in parser.headers {
                        if header.name.eq_ignore_ascii_case("transfer-encoding")
                            && header.value.eq_ignore_ascii_case(b"chunked")
                        {
                            is_transfer_encoding_chunked = true;
                        }
                        if !is_http2_invalid_headers(header.name) {
                            builder = builder.header(header.name, header.value);
                        }
                    }
                    if matches!(&mut response.payload.body, http::Body::Unread(_))
                        && is_transfer_encoding_chunked
                    {
                        let mut take = http::Body::Read(0..0);
                        mem::swap(&mut take, &mut response.payload.body);
                        let mut body = if let http::Body::Unread(reader) = take {
                            http::Body::Unread(Box::new(http::reader::ChunkedReader::data_only(
                                reader,
                            )))
                        } else {
                            unreachable!();
                        };
                        mem::swap(&mut body, &mut response.payload.body);
                    }
                    let mut send = match respond.send_response(builder.body(()).unwrap(), false) {
                        Ok(send) => send,
                        Err(e) => {
                            log::error!(alpn = "h2", error = e.to_string(); "send_response_error");
                            return;
                        }
                    };
                    loop {
                        let state = response.payload.state();
                        let block = match response
                            .payload
                            .next_block()
                            .await
                            .map(|block| block.map(|cow| cow.to_vec()))
                        {
                            Ok(block) => block,
                            Err(e) => {
                                log::error!(alpn = "h2", error = e.to_string(); "read_block_error");
                                return;
                            }
                        };
                        if matches!(
                            state,
                            http::ReadState::ReadBody | http::ReadState::UnreadBody
                        ) {
                            let (data, is_eos) = if let Some(block) = block {
                                if send.capacity() < block.len() {
                                    send.reserve_capacity(block.len());
                                }
                                (bytes::Bytes::from(block), false)
                            } else {
                                (bytes::Bytes::from_static(b""), true)
                            };
                            if let Err(e) = send.send_data(data, is_eos) {
                                log::error!(alpn = "h2", error = e.to_string(); "send_data_error");
                                return;
                            }
                            if is_eos {
                                break;
                            }
                        }
                    }
                    if response.payload.conn_keep_alive {
                        drop(response);
                        worker.add(provider.endpoint(), outgoing).await;
                    }
                });
            }
            Ok(())
        })
    }

    fn add<'a>(
        &'a mut self,
        endpoint: &'a str,
        conn: <P as PoolTrait>::Item,
    ) -> Pin<Box<dyn Future<Output=()> + Send + 'a>> where
        <P as PoolTrait>::Item: Send,
    {
        Box::pin(async move {
            self.pool.add(endpoint, conn).await;
        })
    }
}

#[inline]
fn new_tls_connector() -> tokio_rustls::TlsConnector {
    tokio_rustls::TlsConnector::from(Arc::clone(&*TLS_CLIENT_CONFIG))
}

pub trait PoolTrait {
    type Item;
    fn get<'a, L>(&'a self, label: &'a L) -> Pin<Box<dyn Future<Output=Option<Self::Item>> + Send + 'a>>
    where
        String: Borrow<L>,
        Self::Item: Send,
        L: Ord + Sync + ?Sized;
    fn add<'a, L>(
        &'a self,
        label: &'a L,
        value: Self::Item,
    ) -> Pin<Box<dyn Future<Output=()> + Send + 'a>>
    where
        String: Borrow<L>,
        Self::Item: Send,
        L: ToString + Sync + Ord + ?Sized;
}

impl<P> Worker<P>
where
    P: PoolTrait,
    <P as PoolTrait>::Item: ConnTrait + Send,
{
    async fn select(&mut self, endpoint: &str) -> Option<<P as PoolTrait>::Item> {
        let mut retry_times = 0;
        while retry_times < 3 {
            let Some(mut conn) = self.pool.get(endpoint).await else {
                retry_times += 1;
                continue;
            };
            if conn.health_check().await.is_ok() {
                return Some(conn);
            } else {
                ConnTrait::shutdown(&mut conn).await;
            }
            retry_times += 1;
        }
        None
    }
}

pub trait ConnTrait: AsyncRead + AsyncWrite {
    fn new(endpoint: &str, stream: TcpStream) -> Self;
    fn new_tls(
        endpoint: &str,
        stream: TcpStream,
        connector: tokio_rustls::TlsConnector,
    ) -> Pin<Box<dyn Future<Output=Result<Self, Error>> + Send>>
    where
        Self: Sized;
    fn endpoint(&self) -> &str;
    fn health_check<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output=Result<(), Error>> + Send + 'a>>;
    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=()> + Send + 'a>>;
}

pub struct Conn {
    endpoint: String,
    stream: Stream,
}

impl ConnTrait for Conn {
    fn new(endpoint: &str, stream: TcpStream) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            stream: Stream::Tcp(stream),
        }
    }

    fn new_tls(
        endpoint: &str,
        stream: TcpStream,
        connector: tokio_rustls::TlsConnector,
    ) -> Pin<Box<dyn Future<Output=Result<Self, Error>> + Send>> {
        let endpoint = endpoint.to_owned();
        Box::pin(async move {
            let tls_stream = connector
                .connect(endpoint.clone().try_into().unwrap(), stream)
                .await?;
            Ok(Self {
                endpoint: endpoint.to_string(),
                stream: Stream::Tls(tls_stream),
            })
        })
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn health_check<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output=Result<(), Error>> + Send + 'a>> {
        Box::pin(async {
            self.stream.write_all(b"GET / HTTP/1.1\r\n").await?;
            self.stream.write_all(b"Host: ").await?;
            self.stream.write_all(self.endpoint.as_bytes()).await?;
            self.stream.write_all(b"\r\n").await?;
            self.stream
                .write_all(b"Connection: keep-alive\r\n\r\n")
                .await?;
            self.stream.flush().await?;
            let mut response = http::Response::new(&mut self.stream).await?;
            response.write_to(&mut io::empty()).await?;
            let conn_keep_alive = response.payload.conn_keep_alive;
            drop(response);
            if !conn_keep_alive {
                return Err(Error::IO(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "",
                )));
            }
            Ok(())
        })
    }

    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=()> + Send + 'a>> {
        Box::pin(async {
            match &mut self.stream {
                Stream::Tcp(stream) => {
                    #[allow(unused)]
                    stream.shutdown().await;
                }
                Stream::Tls(stream) => {
                    #[allow(unused)]
                    stream.shutdown().await;
                }
            }
        })
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        pin!(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        pin!(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        pin!(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        pin!(&mut self.stream).poll_shutdown(cx)
    }
}

enum Stream {
    Tcp(TcpStream),
    Tls(TlsOutgoingStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_read(cx, buf),
            Stream::Tls(stream) => pin!(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_write(cx, buf),
            Stream::Tls(stream) => pin!(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_flush(cx),
            Stream::Tls(stream) => pin!(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_shutdown(cx),
            Stream::Tls(stream) => pin!(stream).poll_shutdown(cx),
        }
    }
}

struct H2StreamReader {
    bytes: Option<Cursor<bytes::Bytes>>,
    stream: h2::RecvStream,
}

impl H2StreamReader {
    fn new(stream: h2::RecvStream) -> Self {
        H2StreamReader {
            bytes: None,
            stream,
        }
    }
}

impl AsyncRead for H2StreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(cursor) = &mut self.bytes {
            if cursor.has_remaining() {
                return pin!(cursor).poll_read(cx, buf);
            }
        }
        let stream = match self.stream.poll_data(cx) {
            Poll::Ready(Some(Ok(stream))) => stream,
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => return Poll::Ready(Ok(())),
            Poll::Pending => return Poll::Pending,
        };
        self.bytes = Some(Cursor::new(stream));
        self.poll_read(cx, buf)
    }
}

#[inline]
fn is_http2_invalid_headers(key: &str) -> bool {
    key.eq_ignore_ascii_case(httplib::header::CONNECTION.as_str())
        || key.eq_ignore_ascii_case(httplib::header::TRANSFER_ENCODING.as_str())
        || key.eq_ignore_ascii_case(httplib::header::UPGRADE.as_str())
        || key.eq_ignore_ascii_case("keep-alive")
        || key.eq_ignore_ascii_case("proxy-connection")
        || key.eq_ignore_ascii_case("content-length")
}
