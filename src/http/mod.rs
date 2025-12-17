pub mod reader;

use std::borrow::Cow;
use std::io::Cursor;
use std::ops::Range;
use std::pin::pin;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Error;

use reader::{ChunkedReader, LimitedReader};

const DEFAULT_BUFFER_SIZE: usize = 4096;

const CRLF: &[u8] = b"\r\n";

pub(crate) const QUERY_KEY_KEY: &str = "key";

const HEADER_CONTENT_LENGTH: &str = "Content-Length: ";
const HEADER_TRANSFER_ENCODING: &str = "Transfer-Encoding: ";
pub(crate) const HEADER_HOST: &str = "Host: ";
pub(crate) const HEADER_AUTHORIZATION: &str = "Authorization: ";
pub(crate) const HEADER_X_GOOG_API_KEY: &str = "x-goog-api-key: ";
pub(crate) const HEADER_X_API_KEY: &str = "X-API-Key: ";
const HEADER_CONNECTION: &str = "Connection: ";
const HEADER_UPGRADE: &str = "Upgrade: ";
const HEADER_SEC_WEBSOCKET_KEY: &str = "Sec-WebSocket-Key: ";
const HEADER_SEC_WEBSOCKET_VERSION: &str = "Sec-WebSocket-Version: ";
const HEADER_SEC_WEBSOCKET_PROTOCOL: &str = "Sec-WebSocket-Protocol: ";
const HEADER_SEC_WEBSOCKET_EXTENSIONS: &str = "Sec-WebSocket-Extensions: ";
pub(crate) const HEADER_ANTHROPIC_BETA: &str = "anthropic-beta: ";

const TRANSFER_ENCODING_CHUNKED: &str = "chunked";
const CONNECTION_KEEP_ALIVE: &str = "keep-alive";
const UPGRADE_WEBSOCKET: &str = "websocket";
const CONNECTION_UPGRADE: &str = "upgrade";

const HEADER_CONNECTION_KEEP_ALIVE: &[u8] = b"Connection: keep-alive\r\n";

pub struct Request<'a> {
    pub(crate) payload: Payload<'a>,
}

impl<'a> Request<'a> {
    pub async fn new<S: AsyncRead + Unpin + Send + Sync + 'a>(
        stream: S,
    ) -> Result<Request<'a>, Error> {
        Ok(Request {
            payload: Payload::read_from(stream, DEFAULT_BUFFER_SIZE).await?,
        })
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<(), Error> {
        let mut writer = pin!(writer);
        #[cfg(debug_assertions)]
        let mut payload_blocks = Vec::new();
        loop {
            let Some(block) = self.payload.next_block().await? else {
                break;
            };
            if !block.is_empty() {
                #[cfg(debug_assertions)]
                payload_blocks.push(block.to_vec());
                writer.write_all(&block).await?;
            }
        }
        writer.flush().await?;
        #[cfg(debug_assertions)]
        log::info!(payload:serde = payload_blocks; "http_request_blocks");
        Ok(())
    }

    pub fn path(&self) -> &str {
        self.payload.path()
    }

    pub fn host(&self) -> Option<&str> {
        self.payload.host()
    }

    pub fn auth_key(&self) -> Option<&[u8]> {
        self.payload.auth_key()
    }

    pub fn is_websocket_upgrade(&self) -> bool {
        self.payload.is_websocket_upgrade
    }

    /// Get the raw header bytes for forwarding (used for WebSocket upgrade)
    pub fn header_bytes(&self) -> &[u8] {
        &self.payload.internal_buffer[..self.payload.header_length + 2] // +2 for final CRLF
    }
}

pub struct Response<'a> {
    pub(crate) payload: Payload<'a>,
}

impl<'a> Response<'a> {
    pub async fn new<S: AsyncRead + Unpin + Send + Sync + 'a>(
        stream: S,
    ) -> Result<Response<'a>, Error> {
        Ok(Response {
            payload: Payload::read_from(stream, DEFAULT_BUFFER_SIZE).await?,
        })
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<(), Error> {
        let mut writer = pin!(writer);
        #[cfg(debug_assertions)]
        let mut payload_blocks = Vec::new();
        loop {
            let Some(block) = self.payload.next_block().await? else {
                break;
            };
            if !block.is_empty() {
                #[cfg(debug_assertions)]
                payload_blocks.push(block.to_vec());
                writer.write_all(&block).await?;
            }
        }
        writer.flush().await?;
        #[cfg(debug_assertions)]
        log::info!(payload:serde = payload_blocks; "http_response_blocks");
        Ok(())
    }
}

/// WebSocket upgrade information extracted from headers
/// Uses Range<usize> to avoid memory allocation - values are read from the internal buffer
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct WebSocketUpgrade {
    sec_websocket_key: Range<usize>,
    sec_websocket_version: Range<usize>,
    sec_websocket_protocol: Option<Range<usize>>,
    sec_websocket_extensions: Option<Range<usize>>,
}

pub(crate) struct Payload<'a> {
    internal_buffer: Box<[u8]>,
    first_block_length: usize,
    header_length: usize,
    path_range: Range<usize>,
    host_range: Option<Range<usize>>,
    auth_range: Option<Range<usize>>,
    pub(crate) body: Body<'a>,
    state: ReadState,
    /// Ranges of header chunks to output (gaps between filtered headers)
    header_chunks: Vec<Range<usize>>,
    header_current_chunk: usize,
    pub(crate) conn_keep_alive: bool,
    pub(crate) is_websocket_upgrade: bool,
    #[allow(dead_code)]
    pub(crate) websocket_upgrade: Option<WebSocketUpgrade>,
}

macro_rules! select_provider {
    (($host:expr, $path:expr) => $provider:ident) => {
        let p = crate::program();
        let p = p.read().await;
        let Some($provider) = p.select_provider($host, $path) else {
            return Err(Error::NoProviderFound);
        };
    };
}

impl<'a> Payload<'a> {
    async fn read_from<S: AsyncRead + Unpin + Send + Sync + 'a>(
        mut stream: S,
        buffer_size: usize,
    ) -> Result<Payload<'a>, Error> {
        #[inline]
        async fn find_full_crlfs<S: AsyncRead + Unpin + Send + Sync>(
            stream: &mut S,
            block: &mut [u8],
        ) -> Result<(Vec<usize>, usize), Error> {
            let mut n = 0;
            loop {
                n += match pin!(&mut *stream).read(&mut block[n..]).await {
                    Ok(0) => return Err(Error::InvalidHeader),
                    Ok(n) => n,
                    Err(e) => return Err(e.into()),
                };
                if let Some(crlfs) = find_crlfs(&block[..n]) {
                    return Ok((crlfs, n));
                } else if n >= block.len() {
                    return Err(Error::HeaderTooLarge);
                } else {
                    continue;
                };
            }
        }
        let mut block = vec![0; buffer_size].into_boxed_slice();
        let (crlfs, advanced) = find_full_crlfs(&mut stream, &mut block).await?;
        let Some(&first_double_crlf_index) = crlfs.last() else {
            return Err(Error::HeaderTooLarge);
        };
        let first_block = &block[..advanced];
        let header = &block[..first_double_crlf_index + CRLF.len()];
        let mut header_lines = HeaderLines::new(&crlfs, header);
        let mut content_length: Option<usize> = None;
        let mut transfer_encoding_chunked = false;
        let mut host_range: Option<Range<usize>> = None;
        let mut auth_range: Option<Range<usize>> = None;
        let mut filtered_headers: Vec<Range<usize>> = Vec::new();
        let mut conn_keep_alive = false;
        // WebSocket upgrade detection
        let mut is_upgrade_websocket = false;
        let mut is_connection_upgrade = false;
        let mut sec_websocket_key: Option<Range<usize>> = None;
        let mut sec_websocket_version: Option<Range<usize>> = None;
        let mut sec_websocket_protocol: Option<Range<usize>> = None;
        let mut sec_websocket_extensions: Option<Range<usize>> = None;
        let Some(req_line) = header_lines.next() else {
            return Err(Error::InvalidHeader);
        };
        for line in header_lines {
            let Ok(header) = std::str::from_utf8(line) else {
                return Err(Error::InvalidHeader);
            };
            if is_header(header, HEADER_CONTENT_LENGTH) {
                content_length = match header[HEADER_CONTENT_LENGTH.len()..].parse() {
                    Ok(length) => Some(length),
                    Err(_) => return Err(Error::InvalidHeader),
                }
            } else if is_header(header, HEADER_TRANSFER_ENCODING) {
                if header[HEADER_TRANSFER_ENCODING.len()..].contains(TRANSFER_ENCODING_CHUNKED) {
                    transfer_encoding_chunked = true;
                }
            } else if is_header(header, HEADER_HOST) {
                let start = {
                    let block_start = &block[0] as *const u8 as usize;
                    let host_start = &line[0] as *const u8 as usize;
                    host_start - block_start
                };
                filtered_headers.push(start..start + line.len());
                host_range = Some(start..start + line.len());
            } else if is_header(header, HEADER_CONNECTION) {
                let start = {
                    let block_start = &block[0] as *const u8 as usize;
                    let connection_start = &line[0] as *const u8 as usize;
                    connection_start - block_start
                };
                filtered_headers.push(start..start + line.len());
                let connection_value = &header[HEADER_CONNECTION.len()..];
                if connection_value.eq_ignore_ascii_case(CONNECTION_KEEP_ALIVE) {
                    conn_keep_alive = true;
                }
                // Check for Connection: Upgrade (case-insensitive, may be comma-separated)
                if connection_value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(CONNECTION_UPGRADE))
                {
                    is_connection_upgrade = true;
                }
            } else if is_header(header, HEADER_UPGRADE) {
                let upgrade_value = &header[HEADER_UPGRADE.len()..];
                if upgrade_value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(UPGRADE_WEBSOCKET))
                {
                    is_upgrade_websocket = true;
                }
            } else if is_header(header, HEADER_SEC_WEBSOCKET_KEY) {
                let start = {
                    let block_start = &block[0] as *const u8 as usize;
                    let value_start = &line[HEADER_SEC_WEBSOCKET_KEY.len()] as *const u8 as usize;
                    value_start - block_start
                };
                sec_websocket_key =
                    Some(start..start + line.len() - HEADER_SEC_WEBSOCKET_KEY.len());
            } else if is_header(header, HEADER_SEC_WEBSOCKET_VERSION) {
                let start = {
                    let block_start = &block[0] as *const u8 as usize;
                    let value_start =
                        &line[HEADER_SEC_WEBSOCKET_VERSION.len()] as *const u8 as usize;
                    value_start - block_start
                };
                sec_websocket_version =
                    Some(start..start + line.len() - HEADER_SEC_WEBSOCKET_VERSION.len());
            } else if is_header(header, HEADER_SEC_WEBSOCKET_PROTOCOL) {
                let start = {
                    let block_start = &block[0] as *const u8 as usize;
                    let value_start =
                        &line[HEADER_SEC_WEBSOCKET_PROTOCOL.len()] as *const u8 as usize;
                    value_start - block_start
                };
                sec_websocket_protocol =
                    Some(start..start + line.len() - HEADER_SEC_WEBSOCKET_PROTOCOL.len());
            } else if is_header(header, HEADER_SEC_WEBSOCKET_EXTENSIONS) {
                let start = {
                    let block_start = &block[0] as *const u8 as usize;
                    let value_start =
                        &line[HEADER_SEC_WEBSOCKET_EXTENSIONS.len()] as *const u8 as usize;
                    value_start - block_start
                };
                sec_websocket_extensions =
                    Some(start..start + line.len() - HEADER_SEC_WEBSOCKET_EXTENSIONS.len());
            }
        }
        let Ok(req_line_str) = std::str::from_utf8(req_line) else {
            return Err(Error::InvalidHeader);
        };
        let path_range = get_req_path(req_line_str);
        let path = &req_line_str[path_range.start..path_range.end];
        if let Some(host) = get_host(
            host_range
                .as_ref()
                .map(|range| &block[range.start..range.end]),
        ) {
            select_provider!((host, path) => provider);
            if provider.has_auth_keys() {
                // Due to the particularity of Gemini (aka googleapis), we will first match the
                // corresponding Authorization information from the Headers. If there is no
                // Authorization information in the Headers, we will then try to match the key
                // information from the Query.
                if let Some(auth_header_key) = provider.auth_header_key() {
                    let header_lines = HeaderLines::new(&crlfs, header);
                    for line in header_lines.skip(1) {
                        let Ok(header) = std::str::from_utf8(line) else {
                            return Err(Error::InvalidHeader);
                        };
                        if is_header(header, auth_header_key) {
                            let start = {
                                let block_start = &block[0] as *const u8 as usize;
                                let auth_start = &line[0] as *const u8 as usize;
                                auth_start - block_start
                            };
                            filtered_headers.push(start..start + line.len());
                            auth_range = Some(start..start + line.len());
                        }
                    }
                }
                if auth_range.is_none() {
                    if let Some(auth_query_key) = provider.auth_query_key() {
                        let Some(request_line) = HeaderLines::new(&crlfs, header).next() else {
                            return Err(Error::InvalidHeader);
                        };
                        let Ok(request_line_str) = std::str::from_utf8(request_line) else {
                            return Err(Error::InvalidHeader);
                        };
                        auth_range = get_auth_query_range(request_line_str, auth_query_key);
                    }
                }
            }
            // Filter out extra headers that will be transformed/replaced
            // (e.g., anthropic-beta for Anthropic OAuth)
            let extra_header_keys = provider.extra_headers();
            for extra_key in &extra_header_keys {
                let header_lines = HeaderLines::new(&crlfs, header);
                for line in header_lines.skip(1) {
                    let Ok(header_str) = std::str::from_utf8(line) else {
                        continue;
                    };
                    if is_header(header_str, extra_key) {
                        let start = {
                            let block_start = &block[0] as *const u8 as usize;
                            let extra_header_start = &line[0] as *const u8 as usize;
                            extra_header_start - block_start
                        };
                        filtered_headers.push(start..start + line.len());
                        break;
                    }
                }
            }
        };
        // Security: Reject requests with both Content-Length and Transfer-Encoding headers
        // to prevent HTTP request smuggling attacks (RFC 7230 Section 3.3.3)
        if content_length.is_some() && transfer_encoding_chunked {
            return Err(Error::InvalidHeader);
        }
        let mut first_block_length = advanced;
        let header_length = header.len();
        let body = if let Some(real_content_length) = content_length {
            let block_remaining_size = first_block.len() - (header_length + CRLF.len());
            if real_content_length > block_remaining_size {
                Body::Unread(Box::new(LimitedReader::new(
                    stream,
                    real_content_length - block_remaining_size,
                )))
            } else {
                let start = header_length + CRLF.len();
                let end = start + real_content_length;
                Body::Read(start..end)
            }
        } else {
            let unread: Box<dyn AsyncRead + Unpin + Send + Sync> = {
                let (start, end) = (header_length + CRLF.len(), first_block_length);
                first_block_length = start;
                if start < end {
                    let already_read = Cursor::new(block[start..end].to_vec());
                    Box::new(already_read.chain(stream))
                } else {
                    Box::new(stream)
                }
            };
            if transfer_encoding_chunked {
                Body::Unread(Box::new(ChunkedReader::new(unread)))
            } else {
                // If there is neither a Content-Length nor a chunked Transfer-Encoding, we consider
                // it as not carrying a request body.
                //
                // Typically, when the request comes from h2, even if there is no Content-Length, we
                // will manually add a Transfer-Encoding: chunked header (although in h2,
                // Transfer-Encoding is not a valid header).
                Body::Read(0..0)
            }
        };
        // Build WebSocket upgrade info if this is a valid WebSocket upgrade request
        let is_websocket_upgrade = is_upgrade_websocket && is_connection_upgrade;
        let websocket_upgrade = if is_websocket_upgrade {
            if let (Some(key), Some(version)) = (sec_websocket_key, sec_websocket_version) {
                Some(WebSocketUpgrade {
                    sec_websocket_key: key,
                    sec_websocket_version: version,
                    sec_websocket_protocol,
                    sec_websocket_extensions,
                })
            } else {
                None
            }
        } else {
            None
        };

        Ok(Payload {
            internal_buffer: block,
            first_block_length,
            header_length,
            path_range,
            host_range,
            auth_range,
            body,
            state: ReadState::Start,
            header_chunks: split_header_chunks(filtered_headers, header_length),
            header_current_chunk: 0,
            conn_keep_alive,
            is_websocket_upgrade,
            websocket_upgrade,
        })
    }

    fn path(&self) -> &str {
        if self.path_range.start == self.path_range.end {
            "/"
        } else {
            unsafe {
                std::str::from_utf8_unchecked(
                    &self.internal_buffer[self.path_range.start..self.path_range.end],
                )
            }
        }
    }

    fn host(&self) -> Option<&str> {
        get_host(self.host_header())
    }

    fn host_header(&self) -> Option<&[u8]> {
        if let Some(ref range) = self.host_range {
            Some(&self.internal_buffer[range.start..range.end])
        } else {
            None
        }
    }

    fn auth_key(&self) -> Option<&[u8]> {
        if let Some(ref range) = self.auth_range {
            Some(&self.internal_buffer[range.start..range.end])
        } else {
            None
        }
    }

    pub(crate) fn block(&self) -> &[u8] {
        self.internal_buffer.as_ref()
    }

    /// Find the value of a header by name (case-insensitive).
    /// Returns the header value without the header name prefix.
    fn find_header_value(&self, header_name: &[u8]) -> Option<String> {
        let header = &self.internal_buffer[..self.header_length];
        let header_str = std::str::from_utf8(header).ok()?;

        // Create a search pattern like "anthropic-beta: " (case-insensitive)
        let search_pattern = format!("{}: ", String::from_utf8_lossy(header_name));

        for line in header_str.split("\r\n") {
            if line.len() >= search_pattern.len()
                && line[..search_pattern.len()].eq_ignore_ascii_case(&search_pattern)
            {
                return Some(line[search_pattern.len()..].to_string());
            }
        }
        None
    }

    pub(crate) async fn next_block(&mut self) -> Result<Option<Cow<'_, [u8]>>, Error> {
        match self.state {
            ReadState::Start => {
                if self.header_current_chunk < self.header_chunks.len() {
                    let range = &self.header_chunks[self.header_current_chunk];
                    let cur_idx = self.header_current_chunk;
                    self.header_current_chunk += 1;
                    #[cfg(debug_assertions)]
                    log::info!(step = "ReadState::Start"; "current_block:header_chunks({})", cur_idx);
                    if cur_idx == 0 && self.host_range.is_some() {
                        select_provider!((self.host().unwrap(), self.path()) => provider);
                        if let Some(rewritten) = provider.rewrite_first_header_block(
                            &self.internal_buffer[range.start..range.end],
                        ) {
                            return Ok(Some(Cow::Owned(rewritten)));
                        }
                    }
                    return Ok(Some(Cow::Borrowed(
                        &self.internal_buffer[range.start..range.end],
                    )));
                }
                self.state = ReadState::HostHeader;
                Box::pin(self.next_block()).await
            }
            ReadState::HostHeader => {
                self.state = ReadState::AuthHeader;
                if self.host_range.is_some() {
                    #[cfg(debug_assertions)]
                    log::info!(step = "ReadState::HostHeader"; "current_block:host_header");
                    select_provider!((self.host().unwrap(), self.path()) => provider);
                    Ok(Some(Cow::Owned(provider.host_header().as_bytes().to_vec())))
                } else {
                    Box::pin(self.next_block()).await
                }
            }
            ReadState::AuthHeader => {
                self.state = ReadState::ConnectionHeader;
                if self.host_range.is_some() {
                    #[cfg(debug_assertions)]
                    log::info!(step = "ReadState::AuthHeader"; "current_block:auth_header");
                    select_provider!((self.host().unwrap(), self.path()) => provider);

                    let mut result = Vec::new();

                    // Get auth header (either static or dynamic)
                    if provider.uses_dynamic_auth() {
                        match provider.get_dynamic_auth_header() {
                            Ok(auth_header) => {
                                result.extend_from_slice(auth_header.as_bytes());
                            }
                            Err(e) => {
                                log::error!(error = e.to_string(); "failed_to_get_dynamic_auth_header");
                                return Err(Error::DynamicAuthFailed);
                            }
                        }
                    } else if let Some(auth_header) = provider.auth_header() {
                        result.extend_from_slice(auth_header.as_bytes());
                    }

                    // Transform extra headers (e.g., add anthropic-beta for OAuth)
                    for header_key in provider.extra_headers() {
                        let existing_value =
                            self.find_header_value(header_key.trim_end_matches(": ").as_bytes());
                        if let Some(new_header) =
                            provider.transform_extra_header(header_key, existing_value.as_deref())
                        {
                            result.extend_from_slice(new_header.as_bytes());
                        }
                    }

                    if !result.is_empty() {
                        Ok(Some(Cow::Owned(result)))
                    } else {
                        Box::pin(self.next_block()).await
                    }
                } else {
                    Box::pin(self.next_block()).await
                }
            }
            ReadState::ConnectionHeader => {
                self.state = ReadState::FinishHeader;
                #[cfg(debug_assertions)]
                log::info!(step = "ReadState::ConnectionHeader"; "current_block:connection_header");
                Ok(Some(Cow::Borrowed(HEADER_CONNECTION_KEEP_ALIVE)))
            }
            ReadState::FinishHeader => {
                self.state = ReadState::ReadBody;
                #[cfg(debug_assertions)]
                log::info!(step = "ReadState::FinishHeader"; "current_block:finish_header");
                Ok(Some(Cow::Borrowed(CRLF)))
            }
            ReadState::ReadBody => {
                self.state = ReadState::UnreadBody;
                match &self.body {
                    Body::Read(range) => {
                        #[cfg(debug_assertions)]
                        log::info!(step = "ReadState::ReadBody"; "current_block:total_body_already_been_read");
                        Ok(Some(Cow::Borrowed(
                            &self.internal_buffer[range.start..range.end],
                        )))
                    }
                    Body::Unread(_) => {
                        let (start, end) =
                            (self.header_length + CRLF.len(), self.first_block_length);
                        if start < end {
                            #[cfg(debug_assertions)]
                            log::info!(step = "ReadState::ReadBody"; "current_block:body_already_been_read");
                            Ok(Some(Cow::Borrowed(&self.internal_buffer[start..end])))
                        } else {
                            Box::pin(self.next_block()).await
                        }
                    }
                }
            }
            ReadState::UnreadBody => {
                if let Body::Unread(ref mut reader) = &mut self.body {
                    match pin!(reader).read(&mut self.internal_buffer).await {
                        Ok(0) => Ok(None),
                        Ok(n) => {
                            #[cfg(debug_assertions)]
                            log::info!(step = "ReadState::UnreadBody"; "current_block:body_in_stream");
                            Ok(Some(Cow::Borrowed(&self.internal_buffer[..n])))
                        }
                        Err(e) => Err(e.into()),
                    }
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[inline]
fn get_host(header: Option<&[u8]>) -> Option<&str> {
    header
        .and_then(|header| std::str::from_utf8(header).ok())
        .map(|host| {
            if host.len() >= HEADER_HOST.len()
                && host[..HEADER_HOST.len()].eq_ignore_ascii_case(HEADER_HOST)
            {
                &host[HEADER_HOST.len()..]
            } else {
                host
            }
        })
}

pub(crate) fn split_host_path(host: &str) -> (&str, Option<&str>) {
    if let Some(slash_idx) = host.find('/') {
        let (host_part, path_part) = host.split_at(slash_idx);
        (host_part, Some(path_part.trim_end_matches('/')))
    } else {
        (host, None)
    }
}

/// Strip port from host string (e.g., "localhost:8443" -> "localhost")
#[inline]
pub(crate) fn strip_port(host: &str) -> &str {
    // Handle IPv6 addresses like [::1]:8080
    if let Some(bracket_idx) = host.rfind(']') {
        if let Some(colon_idx) = host[bracket_idx..].find(':') {
            return &host[..bracket_idx + colon_idx];
        }
        return host;
    }
    // Handle regular host:port
    if let Some(colon_idx) = host.rfind(':') {
        return &host[..colon_idx];
    }
    host
}

pub(crate) fn get_req_path(header: &str) -> Range<usize> {
    // Extract URL part (between first and second space)
    let (url_start, url_end) = if let Some(first_whitespace_idx) = header.find(' ') {
        let second_whitespace_idx = {
            if let Some(idx) = header[first_whitespace_idx + 1..].find(' ') {
                first_whitespace_idx + 1 + idx
            } else {
                header.len()
            }
        };
        (first_whitespace_idx + 1, second_whitespace_idx)
    } else {
        (0, header.len())
    };

    let url = &header[url_start..url_end];
    let mut current_offset = url_start;

    // Remove http:// or https:// prefix
    if url.starts_with("http://") {
        current_offset += 7;
    } else if url.starts_with("https://") {
        current_offset += 8;
    }

    let url_without_protocol = &header[current_offset..url_end];

    // Find the path part (after the first '/')
    let Some(path_start_relative) = url_without_protocol.find('/') else {
        return Default::default();
    };

    let path_start = current_offset + path_start_relative;
    let path = &header[path_start..url_end];

    // Remove query parameters (after '?')
    let path_end = if let Some(question_mark_idx) = path.find('?') {
        path_start + question_mark_idx
    } else {
        path_start + path.len()
    };

    // Remove fragment (after '#')
    let final_path_end = if let Some(pound_sign_idx) = header[path_start..path_end].find('#') {
        path_start + pound_sign_idx
    } else {
        path_end
    };

    path_start..final_path_end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_host_path() {
        // Test with path
        let (host, path) = split_host_path("api.openai.com/v1");
        assert_eq!(host, "api.openai.com");
        assert_eq!(path, Some("/v1"));

        // Test without path
        let (host, path) = split_host_path("api.openai.com");
        assert_eq!(host, "api.openai.com");
        assert_eq!(path, None);

        // Test with complex path
        let (host, path) = split_host_path("localhost:8080/api/v1/test");
        assert_eq!(host, "localhost:8080");
        assert_eq!(path, Some("/api/v1/test"));

        // Test with trailing slash
        let (host, path) = split_host_path("api.openai.com/v1/");
        assert_eq!(host, "api.openai.com");
        assert_eq!(path, Some("/v1"));

        // Test with multiple trailing slashes
        let (host, path) = split_host_path("api.openai.com/v1///");
        assert_eq!(host, "api.openai.com");
        assert_eq!(path, Some("/v1"));

        // Test root path only
        let (host, path) = split_host_path("api.openai.com/");
        assert_eq!(host, "api.openai.com");
        assert_eq!(path, Some(""));
    }

    #[test]
    fn test_get_req_path() {
        // Test basic GET request
        let header = "GET /v1/completions HTTP/1.1";
        let range = get_req_path(header);
        assert_eq!(&header[range], "/v1/completions");

        // Test POST request
        let header = "POST /api/users HTTP/1.1";
        let range = get_req_path(header);
        assert_eq!(&header[range], "/api/users");

        // Test with query parameters
        let header = "GET /v1/completions?model=gpt-4 HTTP/1.1";
        let range = get_req_path(header);
        assert_eq!(&header[range], "/v1/completions");

        // Test with fragment
        let header = "GET /v1/models#section HTTP/1.1";
        let range = get_req_path(header);
        assert_eq!(&header[range], "/v1/models");

        // Test root path
        let header = "GET / HTTP/1.1";
        let range = get_req_path(header);
        assert_eq!(&header[range], "/");

        // Test with full URL
        let header = "GET https://api.openai.com/v1/completions HTTP/1.1";
        let range = get_req_path(header);
        assert_eq!(&header[range], "/v1/completions");

        // Test with http:// prefix
        let header = "GET http://localhost:8080/api/test HTTP/1.1";
        let range = get_req_path(header);
        assert_eq!(&header[range], "/api/test");

        // Test complex path with query and fragment
        let header = "GET /v1/completions?key=value&model=gpt-4#section HTTP/1.1";
        let range = get_req_path(header);
        assert_eq!(&header[range], "/v1/completions");

        // Test no path (domain only)
        let header = "GET https://api.openai.com HTTP/1.1";
        let range = get_req_path(header);
        assert_eq!(&header[range], "");
    }

    #[test]
    fn test_strip_port() {
        // Test with port
        assert_eq!(strip_port("localhost:8080"), "localhost");
        assert_eq!(strip_port("api.openai.com:443"), "api.openai.com");
        assert_eq!(strip_port("example.com:8443"), "example.com");

        // Test without port
        assert_eq!(strip_port("localhost"), "localhost");
        assert_eq!(strip_port("api.openai.com"), "api.openai.com");

        // Test IPv6 addresses
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
        assert_eq!(strip_port("[2001:db8::1]:443"), "[2001:db8::1]");
        assert_eq!(strip_port("[fe80::1%eth0]:8080"), "[fe80::1%eth0]");

        // Test IPv6 without port
        assert_eq!(strip_port("[::1]"), "[::1]");
        assert_eq!(strip_port("[2001:db8::1]"), "[2001:db8::1]");
    }

    #[test]
    fn test_get_auth_query_range() {
        // Test basic query parameter
        let header = "GET /v1/models?key=my-api-key HTTP/1.1";
        let range = get_auth_query_range(header, "key");
        assert!(range.is_some());
        assert_eq!(&header[range.unwrap()], "my-api-key");

        // Test multiple query parameters
        let header = "GET /v1/models?model=gpt-4&key=my-api-key&version=2 HTTP/1.1";
        let range = get_auth_query_range(header, "key");
        assert!(range.is_some());
        assert_eq!(&header[range.unwrap()], "my-api-key");

        // Test key at the start
        let header = "GET /v1/models?key=first-key&other=value HTTP/1.1";
        let range = get_auth_query_range(header, "key");
        assert!(range.is_some());
        assert_eq!(&header[range.unwrap()], "first-key");

        // Test missing key
        let header = "GET /v1/models?model=gpt-4 HTTP/1.1";
        let range = get_auth_query_range(header, "key");
        assert!(range.is_none());

        // Test empty value
        let header = "GET /v1/models?key= HTTP/1.1";
        let range = get_auth_query_range(header, "key");
        assert!(range.is_none());

        // Test with fragment
        let header = "GET /v1/models?key=my-key#section HTTP/1.1";
        let range = get_auth_query_range(header, "key");
        assert!(range.is_some());
        assert_eq!(&header[range.unwrap()], "my-key");

        // Test no query string
        let header = "GET /v1/models HTTP/1.1";
        let range = get_auth_query_range(header, "key");
        assert!(range.is_none());
    }

    #[test]
    fn test_is_header() {
        // Test matching headers (case-insensitive)
        assert!(is_header("Host: example.com", HEADER_HOST));
        assert!(is_header("host: example.com", HEADER_HOST));
        assert!(is_header("HOST: example.com", HEADER_HOST));

        // Test Content-Length header
        assert!(is_header("Content-Length: 100", HEADER_CONTENT_LENGTH));
        assert!(is_header("content-length: 100", HEADER_CONTENT_LENGTH));

        // Test Authorization header
        assert!(is_header(
            "Authorization: Bearer token",
            HEADER_AUTHORIZATION
        ));
        assert!(is_header(
            "authorization: Bearer token",
            HEADER_AUTHORIZATION
        ));

        // Test non-matching headers
        assert!(!is_header("Content-Type: application/json", HEADER_HOST));
        assert!(!is_header("X-Custom: value", HEADER_AUTHORIZATION));

        // Test header that's a prefix of another
        assert!(!is_header("Ho", HEADER_HOST));
        assert!(!is_header("Host", HEADER_HOST)); // Missing colon and space
    }

    #[test]
    fn test_find_crlfs() {
        // Test with single CRLF (no double CRLF to end headers)
        let buffer = b"Line1\r\nLine2";
        let result = find_crlfs(buffer);
        assert!(result.is_none()); // Need double CRLF to be valid

        // Test with double CRLF (end of headers) - just the minimal case
        // "Host: example.com\r\n\r\n" = 17 chars + \r\n + \r\n = 21 bytes
        // CRLF positions: 17 and 19
        // 17 + 2 == 19, so it's a terminating double CRLF
        // Result includes only the first CRLF of each line
        let buffer = b"Host: example.com\r\n\r\n";
        let result = find_crlfs(buffer);
        assert!(result.is_some());
        let crlfs = result.unwrap();
        assert_eq!(crlfs.len(), 1);
        assert_eq!(crlfs[0], 17);

        // Test with multiple headers
        // "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
        // Let's count byte positions:
        // "GET / HTTP/1.1" = 14 chars, CRLF at 14
        // "Host: example.com" = 17 chars, at offset 16, CRLF at 16+17=33
        // "Connection: keep-alive" = 22 chars, at offset 35, CRLF at 35+22=57
        // Final \r\n at 59
        // 57 + 2 == 59, so the terminating double CRLF is at 57,59
        let buffer = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        let result = find_crlfs(buffer);
        assert!(result.is_some());
        let crlfs = result.unwrap();
        assert_eq!(crlfs.len(), 3);
        assert_eq!(crlfs[0], 14);
        assert_eq!(crlfs[1], 33);
        assert_eq!(crlfs[2], 57);

        // Test empty buffer
        let buffer = b"";
        let result = find_crlfs(buffer);
        assert!(result.is_none());

        // Test no CRLF
        let buffer = b"No line breaks here";
        let result = find_crlfs(buffer);
        assert!(result.is_none());
    }

    #[test]
    fn test_split_header_chunks() {
        // Test with no filtered headers
        let filtered: Vec<Range<usize>> = vec![];
        let result = split_header_chunks(filtered, 100);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0..100);

        // Test with one filtered header (Host)
        let filtered = vec![20..40];
        let result = split_header_chunks(filtered, 100);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], 0..20);
        assert_eq!(result[1], 42..100); // +2 for CRLF

        // Test with two filtered headers (Host and Auth)
        let filtered = vec![20..40, 50..70];
        let result = split_header_chunks(filtered, 100);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], 0..20);
        assert_eq!(result[1], 42..50);
        assert_eq!(result[2], 72..100);

        // Test with three filtered headers (Host, Auth, Connection)
        let filtered = vec![20..40, 50..70, 80..95];
        let result = split_header_chunks(filtered, 100);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], 0..20);
        assert_eq!(result[1], 42..50);
        assert_eq!(result[2], 72..80);
        assert_eq!(result[3], 97..100);

        // Test with four filtered headers
        let filtered = vec![20..40, 50..70, 80..95, 105..120];
        let result = split_header_chunks(filtered, 130);
        assert_eq!(result.len(), 5);
        assert_eq!(result[0], 0..20);
        assert_eq!(result[1], 42..50);
        assert_eq!(result[2], 72..80);
        assert_eq!(result[3], 97..105);
        assert_eq!(result[4], 122..130);

        // Test with unsorted input (should be sorted internally)
        let filtered = vec![50..70, 20..40];
        let result = split_header_chunks(filtered, 100);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], 0..20);
        assert_eq!(result[1], 42..50);
        assert_eq!(result[2], 72..100);

        // Test with many filtered headers (more than the old fixed-size array could hold)
        let filtered = vec![10..20, 30..40, 50..60, 70..80, 90..100, 110..120];
        let result = split_header_chunks(filtered, 150);
        assert_eq!(result.len(), 7);
        assert_eq!(result[0], 0..10);
        assert_eq!(result[1], 22..30);
        assert_eq!(result[2], 42..50);
        assert_eq!(result[3], 62..70);
        assert_eq!(result[4], 82..90);
        assert_eq!(result[5], 102..110);
        assert_eq!(result[6], 122..150);
    }

    #[test]
    fn test_header_lines_iterator() {
        // "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
        // CRLFs at: 14, 33, 57 (as returned by find_crlfs)
        // Line 1: bytes 0..14 = "GET / HTTP/1.1"
        // Line 2: bytes 16..33 = "Host: example.com"  (16 = 14 + 2)
        // Line 3: bytes 35..57 = "Connection: keep-alive"  (35 = 33 + 2)
        let buffer = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        let crlfs = vec![14, 33, 57];
        let header = &buffer[..59]; // Include up to the end of the first CRLF of the terminating pair

        let mut lines = HeaderLines::new(&crlfs, header);

        let line1 = lines.next().unwrap();
        assert_eq!(line1, b"GET / HTTP/1.1");

        let line2 = lines.next().unwrap();
        assert_eq!(line2, b"Host: example.com");

        let line3 = lines.next().unwrap();
        assert_eq!(line3, b"Connection: keep-alive");

        // After consuming all CRLFs tracked, there shouldn't be more lines
        assert!(lines.next().is_none());
    }

    #[test]
    fn test_get_host() {
        // Test with Host header prefix
        assert_eq!(get_host(Some(b"Host: example.com")), Some("example.com"));
        assert_eq!(get_host(Some(b"host: EXAMPLE.COM")), Some("EXAMPLE.COM"));

        // Test without header prefix (raw host)
        assert_eq!(get_host(Some(b"example.com")), Some("example.com"));

        // Test None
        assert_eq!(get_host(None), None);

        // Test invalid UTF-8 (should return None)
        assert_eq!(get_host(Some(&[0xff, 0xfe])), None);
    }

    #[test]
    fn test_get_host_boundary_checks() {
        // Test empty input - should not panic
        assert_eq!(get_host(Some(b"")), Some(""));

        // Test input shorter than "Host: " prefix (6 chars)
        assert_eq!(get_host(Some(b"H")), Some("H"));
        assert_eq!(get_host(Some(b"Ho")), Some("Ho"));
        assert_eq!(get_host(Some(b"Hos")), Some("Hos"));
        assert_eq!(get_host(Some(b"Host")), Some("Host"));
        assert_eq!(get_host(Some(b"Host:")), Some("Host:"));

        // Test input exactly the length of "Host: " prefix (6 chars)
        assert_eq!(get_host(Some(b"Host: ")), Some(""));

        // Test with partial prefix match but shorter
        assert_eq!(get_host(Some(b"host")), Some("host"));
        assert_eq!(get_host(Some(b"HOST")), Some("HOST"));

        // Test with whitespace only
        assert_eq!(get_host(Some(b"   ")), Some("   "));

        // Test with only newlines
        assert_eq!(get_host(Some(b"\r\n")), Some("\r\n"));

        // Test with mixed case prefix that matches
        assert_eq!(get_host(Some(b"HOST: upper.com")), Some("upper.com"));
        assert_eq!(get_host(Some(b"HoSt: mixed.com")), Some("mixed.com"));
    }

    #[test]
    fn test_read_state_copy_clone() {
        let state = ReadState::Start;
        let state_copy = state;
        let state_clone = state.clone();

        // Both should be the same variant
        assert!(matches!(state_copy, ReadState::Start));
        assert!(matches!(state_clone, ReadState::Start));
    }

    #[test]
    fn test_constants() {
        // Verify header constants are correct
        assert_eq!(HEADER_HOST, "Host: ");
        assert_eq!(HEADER_AUTHORIZATION, "Authorization: ");
        assert_eq!(HEADER_X_GOOG_API_KEY, "x-goog-api-key: ");
        assert_eq!(HEADER_X_API_KEY, "X-API-Key: ");
        assert_eq!(HEADER_CONTENT_LENGTH, "Content-Length: ");
        assert_eq!(HEADER_TRANSFER_ENCODING, "Transfer-Encoding: ");
        assert_eq!(HEADER_CONNECTION, "Connection: ");
        assert_eq!(QUERY_KEY_KEY, "key");
    }

    #[test]
    fn test_websocket_constants() {
        // Verify WebSocket-related constants
        assert_eq!(HEADER_UPGRADE, "Upgrade: ");
        assert_eq!(HEADER_SEC_WEBSOCKET_KEY, "Sec-WebSocket-Key: ");
        assert_eq!(HEADER_SEC_WEBSOCKET_VERSION, "Sec-WebSocket-Version: ");
        assert_eq!(HEADER_SEC_WEBSOCKET_PROTOCOL, "Sec-WebSocket-Protocol: ");
        assert_eq!(
            HEADER_SEC_WEBSOCKET_EXTENSIONS,
            "Sec-WebSocket-Extensions: "
        );
        assert_eq!(UPGRADE_WEBSOCKET, "websocket");
        assert_eq!(CONNECTION_UPGRADE, "upgrade");
    }

    #[test]
    fn test_websocket_upgrade_struct() {
        // WebSocketUpgrade now uses Range<usize> for zero-copy parsing
        let upgrade = WebSocketUpgrade {
            sec_websocket_key: 0..24,
            sec_websocket_version: 24..26,
            sec_websocket_protocol: Some(26..30),
            sec_websocket_extensions: None,
        };

        assert_eq!(upgrade.sec_websocket_key, 0..24);
        assert_eq!(upgrade.sec_websocket_version, 24..26);
        assert_eq!(upgrade.sec_websocket_protocol, Some(26..30));
        assert!(upgrade.sec_websocket_extensions.is_none());

        // Test Clone
        let cloned = upgrade.clone();
        assert_eq!(cloned.sec_websocket_key, upgrade.sec_websocket_key);
        assert_eq!(cloned.sec_websocket_version, upgrade.sec_websocket_version);
    }

    #[test]
    fn test_websocket_upgrade_struct_debug() {
        let upgrade = WebSocketUpgrade {
            sec_websocket_key: 0..8,
            sec_websocket_version: 8..10,
            sec_websocket_protocol: None,
            sec_websocket_extensions: None,
        };

        // Test Debug trait
        let debug_str = format!("{:?}", upgrade);
        assert!(debug_str.contains("WebSocketUpgrade"));
    }
}

pub(crate) fn get_auth_query_range(header: &str, key: &str) -> Option<Range<usize>> {
    let url = if let Some(first_whitespace_idx) = header.find(' ') {
        let second_whitespace_idx = {
            if let Some(idx) = header[first_whitespace_idx + 1..].find(' ') {
                first_whitespace_idx + 1 + idx
            } else {
                header.len()
            }
        };
        &header[first_whitespace_idx + 1..second_whitespace_idx]
    } else {
        let next_whitespace_idx = header.find(' ').unwrap_or(header.len());
        &header[..next_whitespace_idx]
    };
    let mut query = if let Some(question_mark_idx) = url.find('?') {
        &url[question_mark_idx + 1..]
    } else {
        url
    };
    if let Some(pound_sign_idx) = query.find('#') {
        query = &query[..pound_sign_idx]
    }
    let parts = query.split('&');
    for part in parts {
        if let Some(equal_sign_idx) = part.find('=') {
            let (qkey, qval) = part.split_at(equal_sign_idx);
            if qkey == key && qval.len() > 1 {
                let start = {
                    let header_start = &header.as_bytes()[0] as *const u8 as usize;
                    let part_start = &qval.as_bytes()[1] as *const u8 as usize;
                    part_start - header_start
                };
                let end = start + (qval.len() - 1);
                return Some(start..end);
            }
        }
    }
    None
}

#[inline]
pub(crate) fn is_header(header: &str, key: &str) -> bool {
    // str could cause `not a char boundary` issue, so we use bytes
    let (header, key) = (header.as_bytes(), key.as_bytes());
    header.len() >= key.len() && header[..key.len()].eq_ignore_ascii_case(key)
}

/// Split the header buffer into chunks, excluding the filtered header ranges.
/// Takes a Vec of filtered header ranges and returns the non-filtered chunks.
#[inline]
fn split_header_chunks(
    mut filtered_headers: Vec<Range<usize>>,
    header_length: usize,
) -> Vec<Range<usize>> {
    if filtered_headers.is_empty() {
        return vec![0..header_length];
    }

    // Sort by start position
    filtered_headers.sort_by_key(|r| r.start);

    let mut chunks = Vec::with_capacity(filtered_headers.len() + 1);
    let mut current_pos = 0;

    for range in filtered_headers {
        // Add chunk before this filtered header (if any)
        if current_pos < range.start {
            chunks.push(current_pos..range.start);
        }
        // Move past this filtered header and its CRLF
        current_pos = range.end + CRLF.len();
    }

    // Add remaining chunk after the last filtered header (if any)
    if current_pos < header_length {
        chunks.push(current_pos..header_length);
    }

    chunks
}

#[inline]
fn find_crlfs(buffer: &[u8]) -> Option<Vec<usize>> {
    let mut crlfs: Vec<usize> = buffer
        .windows(2)
        .enumerate()
        .filter(|(_, window)| window == &CRLF)
        .map(|(i, _)| i)
        .collect();
    if crlfs.is_empty() {
        None
    } else {
        match (0..(crlfs.len() - 1)).find(|&i| crlfs[i] + CRLF.len() == crlfs[i + 1]) {
            Some(end) => {
                crlfs.drain(end + 1..);
                Some(crlfs)
            }
            None => None,
        }
    }
}

struct HeaderLines<'a> {
    crlfs: std::slice::Iter<'a, usize>,
    header: &'a [u8],
    offset: usize,
}

impl<'a> HeaderLines<'a> {
    fn new(crlfs: &'a [usize], header: &'a [u8]) -> Self {
        Self {
            crlfs: crlfs.iter(),
            header,
            offset: 0,
        }
    }
}

impl<'a> Iterator for HeaderLines<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        self.crlfs.next().map(|&idx| {
            let line = &self.header[self.offset..idx];
            self.offset = idx + CRLF.len();
            line
        })
    }
}

pub(crate) enum Body<'a> {
    Read(Range<usize>),
    Unread(Box<dyn AsyncRead + Unpin + Send + Sync + 'a>),
}

#[derive(Copy, Clone)]
pub(crate) enum ReadState {
    Start,
    HostHeader,
    AuthHeader,
    ConnectionHeader,
    FinishHeader,
    ReadBody,
    UnreadBody,
}
