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
const HEADER_HOST: &str = "Host: ";
pub(crate) const HEADER_AUTHORIZATION: &str = "Authorization: ";
pub(crate) const HEADER_X_GOOG_API_KEY: &str = "x-goog-api-key: ";
pub(crate) const HEADER_X_API_KEY: &str = "X-API-Key: ";
const HEADER_CONNECTION: &str = "Connection: ";

const TRANSFER_ENCODING_CHUNKED: &str = "chunked";
const CONNECTION_KEEP_ALIVE: &str = "keep-alive";

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

    pub async fn write_to<W: AsyncWrite + Unpin>(
        &mut self,
        mut writer: &mut W,
    ) -> Result<(), Error> {
        let mut writer = pin!(writer);
        #[cfg(debug_assertions)]
        let mut payload_blocks = Vec::new();
        loop {
            let Some(block) = self.payload.next_block().await? else {
                break;
            };
            if block.len() > 0 {
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

    pub async fn write_to<W: AsyncWrite + Unpin>(
        &mut self,
        mut writer: &mut W,
    ) -> Result<(), Error> {
        let mut writer = pin!(writer);
        #[cfg(debug_assertions)]
        let mut payload_blocks = Vec::new();
        loop {
            let Some(block) = self.payload.next_block().await? else {
                break;
            };
            if block.len() > 0 {
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

pub(crate) struct Payload<'a> {
    internal_buffer: Box<[u8]>,
    first_block_length: usize,
    header_length: usize,
    path_range: Range<usize>,
    host_range: Option<Range<usize>>,
    auth_range: Option<Range<usize>>,
    pub(crate) body: Body<'a>,
    state: ReadState,
    header_chunks: [Option<Range<usize>>; 4],
    header_current_chunk: usize,
    pub(crate) conn_keep_alive: bool,
}

macro_rules! select_provider {
    (($host:expr, $path:expr) => $provider:ident) => {
        let p = crate::program();
        let p = p.read().await;
        let Some($provider) = p.select_provider($host, $path) else {
            return Err(Error::InvalidHeader);
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
                } else {
                    if n >= block.len() {
                        return Err(Error::HeaderTooLarge);
                    } else {
                        continue;
                    }
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
        let mut header_chunks: [Option<Range<usize>>; 4] = [None, None, None, None];
        let mut conn_keep_alive = false;
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
                header_chunks[0] = Some(start..start + line.len());
                host_range = Some(start..start + line.len());
            } else if is_header(header, HEADER_CONNECTION) {
                let start = {
                    let block_start = &block[0] as *const u8 as usize;
                    let connection_start = &line[0] as *const u8 as usize;
                    connection_start - block_start
                };
                header_chunks[2] = Some(start..start + line.len());
                if header[HEADER_CONNECTION.len()..].eq_ignore_ascii_case(CONNECTION_KEEP_ALIVE) {
                    conn_keep_alive = true;
                }
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
                            header_chunks[1] = Some(start..start + line.len());
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
        Ok(Payload {
            internal_buffer: block,
            first_block_length,
            header_length,
            path_range,
            host_range,
            auth_range,
            body,
            state: ReadState::Start,
            header_chunks: split_header_chunks(header_chunks, header_length),
            header_current_chunk: 0,
            conn_keep_alive,
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

    pub(crate) fn state(&self) -> ReadState {
        self.state
    }

    pub(crate) async fn next_block(&mut self) -> Result<Option<Cow<[u8]>>, Error> {
        match self.state {
            ReadState::Start => {
                if self.header_current_chunk < self.header_chunks.len() {
                    if let Some(ref range) = self.header_chunks[self.header_current_chunk] {
                        let cur_idx = self.header_current_chunk;
                        self.header_current_chunk += 1;
                        #[cfg(debug_assertions)]
                        log::info!(step = "ReadState::Start"; "current_block:header_chunks({})", cur_idx);
                        if cur_idx == 0 {
                            if self.host_range.is_some() {
                                select_provider!((self.host().unwrap(), self.path()) => provider);
                                if let Some(rewritten) = provider.rewrite_first_header_block(
                                    &self.internal_buffer[range.start..range.end],
                                ) {
                                    return Ok(Some(Cow::Owned(rewritten)));
                                }
                            }
                        }
                        return Ok(Some(Cow::Borrowed(
                            &self.internal_buffer[range.start..range.end],
                        )));
                    }
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
                    if let Some(auth_header) = provider.auth_header() {
                        Ok(Some(Cow::Owned(auth_header.as_bytes().to_vec())))
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
        .map(|header| std::str::from_utf8(header).ok())
        .flatten()
        .map(|host| {
            if host[..HEADER_HOST.len()].eq_ignore_ascii_case(HEADER_HOST) {
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
        let next_whitespace_idx = header.find(' ').unwrap_or_else(|| header.len());
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

#[inline]
fn split_header_chunks(
    mut header: [Option<Range<usize>>; 4],
    header_length: usize,
) -> [Option<Range<usize>>; 4] {
    header.sort_by_key(|range| range.as_ref().map(|r| r.start).unwrap_or(usize::MAX));
    match header {
        [Some(first), Some(second), Some(third), None] => [
            Some(0..first.start),
            Some(first.end + CRLF.len()..second.start),
            Some(second.end + CRLF.len()..third.start),
            Some(third.end + CRLF.len()..header_length),
        ],
        [Some(first), Some(second), None, None] => [
            Some(0..first.start),
            Some(first.end + CRLF.len()..second.start),
            Some(second.end + CRLF.len()..header_length),
            None,
        ],
        [Some(first), None, None, None] => [
            Some(0..first.start),
            Some(first.end + CRLF.len()..header_length),
            None,
            None,
        ],
        [None, None, None, None] => [Some(0..header_length), None, None, None],
        _ => unreachable!(),
    }
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
