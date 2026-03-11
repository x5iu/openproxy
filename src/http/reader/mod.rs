use std::io::{self};
use std::pin::{pin, Pin};
use std::task::{Context, Poll};

use super::CRLF;

use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

pub trait AsyncBufReadStream: AsyncRead + AsyncBufRead + Unpin + Send + Sync {}

impl<T> AsyncBufReadStream for T where T: AsyncRead + AsyncBufRead + Unpin + Send + Sync {}

pub struct PrefixBufReader<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> PrefixBufReader<R> {
    pub fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin + Send + Sync> AsyncRead for PrefixBufReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.pos < self.prefix.len() {
            let remaining = self.prefix.len() - self.pos;
            let to_copy = remaining.min(buf.remaining());
            let start = self.pos;
            let end = start + to_copy;
            buf.put_slice(&self.prefix[start..end]);
            self.pos = end;
            if self.pos >= self.prefix.len() {
                self.prefix.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        pin!(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R: AsyncBufRead + Unpin + Send + Sync> AsyncBufRead for PrefixBufReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let me = self.get_mut();
        if me.pos < me.prefix.len() {
            return Poll::Ready(Ok(&me.prefix[me.pos..]));
        }
        Pin::new(&mut me.inner).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.get_mut();
        if me.pos < me.prefix.len() {
            let remaining = me.prefix.len() - me.pos;
            let consumed = amt.min(remaining);
            me.pos += consumed;
            if me.pos >= me.prefix.len() {
                me.prefix.clear();
                me.pos = 0;
            }
            if amt > consumed {
                Pin::new(&mut me.inner).consume(amt - consumed);
            }
            return;
        }
        Pin::new(&mut me.inner).consume(amt);
    }
}

pub struct LimitedReader<R> {
    reader: R,
    content_length: usize,
}

impl<R> LimitedReader<R> {
    pub fn new(reader: R, content_length: usize) -> Self {
        Self {
            reader,
            content_length,
        }
    }
}

impl<R: AsyncRead + Unpin + Send + Sync> AsyncRead for LimitedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.content_length == 0 {
            return Poll::Ready(Ok(()));
        }
        let max = std::cmp::min(self.content_length, buf.remaining());
        let mut real_buf = ReadBuf::new(&mut buf.initialize_unfilled()[..max]);
        let ret = pin!(&mut self.reader).poll_read(cx, &mut real_buf)?;
        let n = real_buf.filled().len();
        buf.advance(n);
        self.content_length -= n;
        ret.map(|_| Ok(()))
    }
}

pub struct ChunkedWriter<R> {
    reader: R,
    frame: Vec<u8>,
    buf: Vec<u8>,
    pos: usize,
    finished: bool,
}

impl<R> ChunkedWriter<R> {
    const MAX_HEADER_SIZE: usize = 5;
    const MAX_DATA_SIZE: usize = 4096;

    pub fn new(reader: R) -> Self {
        Self {
            reader,
            frame: Vec::with_capacity(
                Self::MAX_HEADER_SIZE + CRLF.len() + Self::MAX_DATA_SIZE + CRLF.len(),
            ),
            buf: Vec::with_capacity(Self::MAX_DATA_SIZE),
            pos: 0,
            finished: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: AsyncRead + Unpin + Send + Sync> AsyncRead for ChunkedWriter<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.pos >= self.frame.len() {
            if self.finished {
                return Poll::Ready(Ok(()));
            }
            let this = &mut *self;
            if this.buf.capacity() < Self::MAX_DATA_SIZE {
                this.buf.reserve(Self::MAX_DATA_SIZE - this.buf.capacity());
            }
            if this.buf.len() < Self::MAX_DATA_SIZE {
                // SAFETY: extend to MAX_DATA_SIZE to obtain a writable buffer; truncate after the read.
                unsafe {
                    this.buf.set_len(Self::MAX_DATA_SIZE);
                }
            }
            let n = {
                let mut rb = ReadBuf::new(&mut this.buf[..Self::MAX_DATA_SIZE]);
                match pin!(&mut this.reader).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => rb.filled().len(),
                    Poll::Ready(Err(e)) => {
                        this.buf.truncate(0);
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        this.buf.truncate(0);
                        return Poll::Pending;
                    }
                }
            };
            this.buf.truncate(n);
            let mut n0 = n;
            let mut i = 0usize;
            #[allow(const_evaluatable_unchecked)]
            let mut hex = [0u8; Self::MAX_HEADER_SIZE];
            if n0 == 0 {
                hex[0] = b'0';
                i = 1;
            } else {
                while n0 > 0 {
                    let d = (n0 & 0xf) as u8;
                    hex[i] = b"0123456789abcdef"[d as usize];
                    i += 1;
                    n0 >>= 4;
                }
                hex[..i].reverse();
            }
            debug_assert!(i <= Self::MAX_HEADER_SIZE);
            let needed = i + CRLF.len() + n + CRLF.len();
            if this.frame.capacity() < needed {
                this.frame.reserve(needed - this.frame.capacity());
            }
            this.frame.clear();
            this.frame.extend_from_slice(&hex[..i]);
            this.frame.extend_from_slice(CRLF);
            // Invariant: only the first `n` bytes of `this.buf` are initialized and used below.
            this.frame.extend_from_slice(&this.buf[..n]);
            this.frame.extend_from_slice(CRLF);
            this.pos = 0;
            if n == 0 {
                this.finished = true;
            }
        }
        let remaining = self.frame.len() - self.pos;
        let to_copy = remaining.min(out.remaining());
        let start = self.pos;
        let end = start + to_copy;
        out.put_slice(&self.frame[start..end]);
        self.pos = end;
        Poll::Ready(Ok(()))
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum ChunkedReadMode {
    NormalizedChunked,
    DataOnly,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum ChunkedReadState {
    ReadChunkHeader,
    ReadChunkData,
    ReadChunkDataCrlf,
    DrainTrailers,
    Finished,
}

// Decodes or normalizes HTTP/1.1 chunked bodies while draining and discarding trailer-part.
// It avoids reading past the exact chunked message boundary so keep-alive parsing stays aligned.
pub struct ChunkedReader<R> {
    mode: ChunkedReadMode,
    reader: R,
    state: ChunkedReadState,
    chunk_remaining: usize,
    pending: Vec<u8>,
    pending_pos: usize,
    line_buf: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin + Send + Sync> ChunkedReader<R> {
    const MAX_LINE_SIZE: usize = 4096;

    pub fn new(reader: R) -> Self {
        Self {
            mode: ChunkedReadMode::NormalizedChunked,
            reader,
            state: ChunkedReadState::ReadChunkHeader,
            chunk_remaining: 0,
            pending: Vec::with_capacity(Self::MAX_LINE_SIZE + CRLF.len()),
            pending_pos: 0,
            line_buf: Vec::with_capacity(Self::MAX_LINE_SIZE),
        }
    }

    pub fn data_only(reader: R) -> ChunkedReader<R> {
        let mut reader = ChunkedReader::new(reader);
        reader.mode = ChunkedReadMode::DataOnly;
        reader
    }

    #[cfg(test)]
    fn into_inner(self) -> R {
        self.reader
    }

    #[inline]
    fn emits_data_only(&self) -> bool {
        self.mode == ChunkedReadMode::DataOnly
    }

    #[inline]
    fn append_pending(&mut self, bytes: &[u8]) {
        if self.pending_pos >= self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        self.pending.extend_from_slice(bytes);
    }

    #[inline]
    fn flush_pending(&mut self, out: &mut ReadBuf<'_>) -> bool {
        if self.pending_pos >= self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
            return false;
        }
        let remaining = self.pending.len() - self.pending_pos;
        let to_copy = remaining.min(out.remaining());
        let start = self.pending_pos;
        let end = start + to_copy;
        out.put_slice(&self.pending[start..end]);
        self.pending_pos = end;
        if self.pending_pos >= self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        true
    }

    #[inline]
    fn parse_chunk_length(line: &[u8]) -> io::Result<usize> {
        let Ok(length_str) = std::str::from_utf8(line) else {
            return Err(io::Error::other("non-utf8 chunk length"));
        };
        usize::from_str_radix(length_str, 16)
            .map_err(|_| io::Error::other(format!("invalid chunk length: \"{}\"", length_str)))
    }

    #[inline]
    fn poll_read_byte(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<u8>> {
        let buffer = match Pin::new(&mut self.reader).poll_fill_buf(cx) {
            Poll::Ready(Ok(buffer)) => buffer,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        if buffer.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            )));
        }
        let byte = buffer[0];
        Pin::new(&mut self.reader).consume(1);
        Poll::Ready(Ok(byte))
    }

    fn poll_read_line(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        loop {
            if self.line_buf.ends_with(CRLF) {
                self.line_buf.truncate(self.line_buf.len() - CRLF.len());
                let line = std::mem::take(&mut self.line_buf);
                return Poll::Ready(Ok(line));
            }
            if self.line_buf.len() >= Self::MAX_LINE_SIZE {
                return Poll::Ready(Err(io::Error::other(format!(
                    "header line too long: scanned {} bytes without CRLF (capacity {})",
                    self.line_buf.len(),
                    Self::MAX_LINE_SIZE
                ))));
            }
            let byte = match self.poll_read_byte(cx) {
                Poll::Ready(Ok(byte)) => byte,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            self.line_buf.push(byte);
        }
    }

    fn poll_expect_crlf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.line_buf.len() < CRLF.len() {
            let byte = match self.poll_read_byte(cx) {
                Poll::Ready(Ok(byte)) => byte,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            self.line_buf.push(byte);
        }
        if self.line_buf.as_slice() != CRLF {
            self.line_buf.clear();
            return Poll::Ready(Err(io::Error::other("invalid chunk delimiter")));
        }
        self.line_buf.clear();
        Poll::Ready(Ok(()))
    }

    fn internal_poll_read(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.flush_pending(out) {
            return Poll::Ready(Ok(()));
        }

        loop {
            match self.state {
                ChunkedReadState::ReadChunkHeader => {
                    let line = match self.poll_read_line(cx) {
                        Poll::Ready(Ok(line)) => line,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    #[cfg(debug_assertions)]
                    log::info!(buffer:serde = line.clone(), index = line.len(); "read_chunk_header_line");
                    let length = match Self::parse_chunk_length(&line) {
                        Ok(length) => length,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    if !self.emits_data_only() {
                        self.append_pending(&line);
                        self.append_pending(CRLF);
                    }
                    self.chunk_remaining = length;
                    self.state = if length == 0 {
                        ChunkedReadState::DrainTrailers
                    } else {
                        ChunkedReadState::ReadChunkData
                    };
                    if self.flush_pending(out) {
                        return Poll::Ready(Ok(()));
                    }
                }
                ChunkedReadState::ReadChunkData => {
                    let max = std::cmp::min(self.chunk_remaining, out.remaining());
                    let mut real_buf = ReadBuf::new(&mut out.initialize_unfilled()[..max]);
                    let poll = pin!(&mut self.reader).poll_read(cx, &mut real_buf)?;
                    match poll {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(()) => {
                            let n = real_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF",
                                )));
                            }
                            self.chunk_remaining -= n;
                            out.advance(n);
                            if self.chunk_remaining == 0 {
                                self.state = ChunkedReadState::ReadChunkDataCrlf;
                            }
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                ChunkedReadState::ReadChunkDataCrlf => match self.poll_expect_crlf(cx) {
                    Poll::Ready(Ok(())) => {
                        if !self.emits_data_only() {
                            self.append_pending(CRLF);
                        }
                        self.state = ChunkedReadState::ReadChunkHeader;
                        if self.flush_pending(out) {
                            return Poll::Ready(Ok(()));
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                ChunkedReadState::DrainTrailers => {
                    let line = match self.poll_read_line(cx) {
                        Poll::Ready(Ok(line)) => line,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    if line.is_empty() {
                        if !self.emits_data_only() {
                            self.append_pending(CRLF);
                        }
                        self.state = ChunkedReadState::Finished;
                        if self.flush_pending(out) {
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                ChunkedReadState::Finished => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<R: AsyncBufRead + Unpin + Send + Sync> AsyncRead for ChunkedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        match this.internal_poll_read(cx, buf) {
            Poll::Ready(Err(e)) => {
                log::error!(error = e.to_string(); "chunked_reader_error");
                Poll::Ready(Err(e))
            }
            ret => ret,
        }
    }
}

pub(crate) mod buf_reader {
    use std::io::{self};
    use std::pin::{pin, Pin};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

    pub(crate) struct BufReader<R: ?Sized> {
        buf: Vec<u8>,
        pos: usize,
        inner: R,
    }

    impl<R> BufReader<R> {
        pub(crate) fn new(inner: R, size: usize) -> Self {
            let buf = Vec::with_capacity(size);
            Self { buf, pos: 0, inner }
        }

        #[cfg(test)]
        pub(crate) fn capacity(&self) -> usize {
            self.buf.capacity()
        }

        #[cfg(test)]
        pub(crate) fn buffer(&self) -> &[u8] {
            &self.buf[self.pos..]
        }

        #[inline]
        fn clear_if_consumed(&mut self) {
            if self.pos >= self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
        }
    }

    impl<R: AsyncRead + Unpin + Send + Sync> AsyncRead for BufReader<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if self.pos >= self.buf.len() {
                self.buf.clear();
                self.pos = 0;
                return pin!(&mut self.inner).poll_read(cx, buf);
            }
            let remaining = self.buf.len() - self.pos;
            let to_copy = remaining.min(buf.remaining());
            let start = self.pos;
            let end = start + to_copy;
            buf.put_slice(&self.buf[start..end]);
            self.pos = end;
            self.clear_if_consumed();
            Poll::Ready(Ok(()))
        }
    }

    impl<R: AsyncWrite + Unpin + Send + Sync> AsyncWrite for BufReader<R> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            pin!(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            pin!(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            pin!(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl<R: AsyncRead + Unpin + Send + Sync> AsyncBufRead for BufReader<R> {
        fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let me = self.get_mut();
            if me.pos >= me.buf.len() {
                me.buf.clear();
                me.pos = 0;
                let cap = me.buf.capacity();
                // SAFETY: temporarily extend the buffer, then truncate based on actual bytes read.
                unsafe {
                    me.buf.set_len(cap);
                }
                let mut buf = ReadBuf::new(&mut me.buf[..cap]);
                match pin!(&mut me.inner).poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        me.buf.truncate(n);
                        me.pos = 0;
                    }
                    Poll::Ready(Err(e)) => {
                        me.buf.truncate(0);
                        me.pos = 0;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        me.buf.truncate(0);
                        me.pos = 0;
                        return Poll::Pending;
                    }
                }
            }
            Poll::Ready(Ok(&me.buf[me.pos..]))
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            let me = self.get_mut();
            let remaining = me.buf.len().saturating_sub(me.pos);
            let consumed = amt.min(remaining);
            me.pos += consumed;
            me.clear_if_consumed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ChunkedReader, ChunkedWriter, LimitedReader};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, ReadBuf};

    struct MemReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl MemReader {
        fn new(data: Vec<u8>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl AsyncRead for MemReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pos >= self.data.len() || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let remaining = self.data.len() - self.pos;
            let to_copy = remaining.min(buf.remaining());
            let end = self.pos + to_copy;
            let src = &self.data[self.pos..end];
            let dst = buf.initialize_unfilled();
            dst[..to_copy].copy_from_slice(src);
            buf.advance(to_copy);
            self.pos = end;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncBufRead for MemReader {
        fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let me = self.get_mut();
            Poll::Ready(Ok(&me.data[me.pos..]))
        }

        fn consume(mut self: Pin<&mut Self>, amt: usize) {
            self.pos = (self.pos + amt).min(self.data.len());
        }
    }

    struct LimitedMemReader {
        inner: MemReader,
        limit_per_poll: usize,
    }

    impl LimitedMemReader {
        fn new(data: Vec<u8>, limit_per_poll: usize) -> Self {
            Self {
                inner: MemReader::new(data),
                limit_per_poll,
            }
        }
    }

    impl AsyncRead for LimitedMemReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let remaining = self.inner.data.len().saturating_sub(self.inner.pos);
            if remaining == 0 {
                return Poll::Ready(Ok(()));
            }
            let to_copy = remaining.min(buf.remaining()).min(self.limit_per_poll);
            let end = self.inner.pos + to_copy;
            let src = &self.inner.data[self.inner.pos..end];
            let dst = buf.initialize_unfilled();
            dst[..to_copy].copy_from_slice(src);
            buf.advance(to_copy);
            self.inner.pos = end;
            Poll::Ready(Ok(()))
        }
    }

    struct PendingOnceReader {
        inner: MemReader,
        pending: bool,
    }

    impl PendingOnceReader {
        fn new(data: Vec<u8>) -> Self {
            Self {
                inner: MemReader::new(data),
                pending: true,
            }
        }
    }

    impl AsyncRead for PendingOnceReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pending {
                self.pending = false;
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    struct PendingNReader {
        inner: MemReader,
        remaining: usize,
    }

    impl PendingNReader {
        fn new(data: Vec<u8>, n: usize) -> Self {
            Self {
                inner: MemReader::new(data),
                remaining: n,
            }
        }
    }

    impl AsyncRead for PendingNReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.remaining > 0 {
                self.remaining -= 1;
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    struct ErrorReader;

    impl AsyncRead for ErrorReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("inner failure")))
        }
    }

    fn noop_waker() -> std::task::Waker {
        unsafe fn clone(_: *const ()) -> std::task::RawWaker {
            std::task::RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: std::task::RawWakerVTable =
            std::task::RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { std::task::Waker::from_raw(std::task::RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    async fn encode_with<R: AsyncRead + Unpin + Send + Sync>(r: R) -> Vec<u8> {
        let mut w = ChunkedWriter::new(r);
        let mut out = Vec::new();
        w.read_to_end(&mut out).await.unwrap();
        out
    }

    async fn decode_chunked(data: Vec<u8>) -> Vec<u8> {
        let r = MemReader::new(data);
        let mut dec = ChunkedReader::data_only(r);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.unwrap();
        out
    }

    fn parse_sizes(mut enc: &[u8]) -> Vec<usize> {
        let mut sizes = Vec::new();
        loop {
            let mut j = 0;
            while j < enc.len() && enc[j] != b'\r' {
                j += 1;
            }
            let len = usize::from_str_radix(std::str::from_utf8(&enc[..j]).unwrap(), 16).unwrap();
            sizes.push(len);
            enc = &enc[j + 2..];
            if len == 0 {
                assert_eq!(&enc[..2], b"\r\n");
                break;
            }
            enc = &enc[len + 2..];
        }
        sizes
    }

    #[tokio::test]
    async fn chunked_writer_roundtrip_various_lengths_and_contents() {
        let mut cases: Vec<Vec<u8>> = Vec::new();
        cases.push(Vec::new());
        for &n in &[1usize, 2, 15, 16, 17, 255, 256, 4095, 4096, 4097, 10_000] {
            let v: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            cases.push(v);
        }
        cases.push(b"hello\r\nworld".to_vec());
        let mut rng = StdRng::seed_from_u64(42);
        let mut rand_bytes = vec![0u8; 12_345];
        rng.fill(&mut rand_bytes[..]);
        cases.push(rand_bytes);

        for data in cases {
            let enc = encode_with(MemReader::new(data.clone())).await;
            assert!(enc.ends_with(b"0\r\n\r\n"));
            let dec = decode_chunked(enc).await;
            assert_eq!(dec, data);
        }
    }

    #[tokio::test]
    async fn chunked_writer_respects_read_boundaries() {
        let data: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        let enc = encode_with(LimitedMemReader::new(data.clone(), 1000)).await;
        let sizes = parse_sizes(&enc);
        assert_eq!(sizes, vec![1000, 1000, 1000, 0]);
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_writer_boundary_4096() {
        let data = vec![1u8; 4096];
        let enc = encode_with(MemReader::new(data.clone())).await;
        assert!(enc.starts_with(b"1000\r\n"));
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_writer_respects_read_boundaries_large_limit() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 251) as u8).collect();
        let enc = encode_with(LimitedMemReader::new(data.clone(), 10000)).await;
        let sizes = parse_sizes(&enc);
        assert_eq!(sizes, vec![4096, 4096, 1808, 0]);
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_writer_small_out_buffer_multiwrite() {
        let data: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
        let mut w = ChunkedWriter::new(MemReader::new(data.clone()));
        let mut enc = Vec::new();
        let mut tmp = [0u8; 2];
        loop {
            let n = AsyncReadExt::read(&mut w, &mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            enc.extend_from_slice(&tmp[..n]);
        }
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_writer_propagates_pending_from_inner() {
        let data: Vec<u8> = (0..128).map(|i| (i % 251) as u8).collect();
        let mut w = ChunkedWriter::new(PendingOnceReader::new(data.clone()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf_space = [0u8; 8];
        let mut rb = ReadBuf::new(&mut buf_space);
        match Pin::new(&mut w).poll_read(&mut cx, &mut rb) {
            Poll::Pending => {}
            _ => panic!("expected Pending on first poll"),
        }
        let before = rb.filled().len();
        assert_eq!(before, 0);
        match Pin::new(&mut w).poll_read(&mut cx, &mut rb) {
            Poll::Ready(Ok(())) => {}
            _ => panic!("expected Ready after second poll"),
        }
        let n = rb.filled().len();
        assert!(n > 0);
        let mut enc = Vec::from(rb.filled());
        let mut tmp = [0u8; 256];
        loop {
            let m = AsyncReadExt::read(&mut w, &mut tmp).await.unwrap();
            if m == 0 {
                break;
            }
            enc.extend_from_slice(&tmp[..m]);
        }
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_writer_propagates_multiple_pendings() {
        let data: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
        let mut w = ChunkedWriter::new(PendingNReader::new(data.clone(), 3));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf_space = [0u8; 16];
        let mut rb = ReadBuf::new(&mut buf_space);
        // First several polls should be Pending
        for _ in 0..3 {
            match Pin::new(&mut w).poll_read(&mut cx, &mut rb) {
                Poll::Pending => {}
                _ => panic!("expected Pending"),
            }
            assert_eq!(rb.filled().len(), 0);
        }
        // Then Ready
        match Pin::new(&mut w).poll_read(&mut cx, &mut rb) {
            Poll::Ready(Ok(())) => {}
            _ => panic!("expected Ready after pendings"),
        }
        let mut enc = Vec::from(rb.filled());
        let mut tmp = [0u8; 256];
        loop {
            let m = AsyncReadExt::read(&mut w, &mut tmp).await.unwrap();
            if m == 0 {
                break;
            }
            enc.extend_from_slice(&tmp[..m]);
        }
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_reader_full_roundtrip_including_headers() {
        let data: Vec<u8> = (0..1234).map(|i| (i % 251) as u8).collect();
        let enc = encode_with(MemReader::new(data.clone())).await;
        let mut rdr = ChunkedReader::new(MemReader::new(enc.clone()));
        let mut out = Vec::new();
        rdr.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, enc);
    }

    #[tokio::test]
    async fn limited_reader_truncates_to_content_length() {
        let data: Vec<u8> = (0..128).map(|i| i as u8).collect();
        let inner = MemReader::new(data.clone());
        let mut limited = LimitedReader::new(inner, 10);
        let mut out = Vec::new();
        AsyncReadExt::read_to_end(&mut limited, &mut out)
            .await
            .unwrap();
        assert_eq!(out.len(), 10);
        assert_eq!(out, data[..10].to_vec());
    }

    #[tokio::test]
    async fn limited_reader_zero_length_yields_empty() {
        let data: Vec<u8> = (0..128).map(|i| i as u8).collect();
        let inner = MemReader::new(data);
        let mut limited = LimitedReader::new(inner, 0);
        let mut out = Vec::new();
        AsyncReadExt::read_to_end(&mut limited, &mut out)
            .await
            .unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn limited_reader_does_not_overread_when_source_shorter_than_limit() {
        let data: Vec<u8> = (0..16).map(|i| i as u8).collect();
        let inner = MemReader::new(data.clone());
        let mut limited = LimitedReader::new(inner, 32);
        let mut out = Vec::new();
        AsyncReadExt::read_to_end(&mut limited, &mut out)
            .await
            .unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn limited_reader_respects_out_buffer_boundaries() {
        let data = vec![1u8; 64];
        let inner = MemReader::new(data.clone());
        let mut limited = LimitedReader::new(inner, 10);
        let mut out = Vec::new();
        let mut tmp = [0u8; 3];
        loop {
            let n = AsyncReadExt::read(&mut limited, &mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(out.len(), 10);
        assert_eq!(out, data[..10].to_vec());
    }

    #[tokio::test]
    async fn chunked_reader_errors_on_non_utf8_length() {
        let mut enc = Vec::new();
        enc.extend_from_slice(&[0xffu8, 0xffu8]);
        enc.extend_from_slice(b"\r\n0\r\n\r\n");
        let r = MemReader::new(enc);
        let mut rdr = ChunkedReader::data_only(r);
        let mut out = Vec::new();
        let err = rdr.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "non-utf8 chunk length");
    }

    #[tokio::test]
    async fn chunked_reader_errors_on_invalid_hex_length() {
        let enc = b"zz\r\n0\r\n\r\n".to_vec();
        let r = MemReader::new(enc);
        let mut rdr = ChunkedReader::data_only(r);
        let mut out = Vec::new();
        let err = rdr.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "invalid chunk length: \"zz\"");
    }

    #[tokio::test]
    async fn chunked_reader_errors_when_header_too_long_without_crlf() {
        let size = 4096;
        let data = vec![b'a'; size];
        let r = MemReader::new(data);
        let mut rdr = ChunkedReader::data_only(r);
        let mut out = Vec::new();
        let err = rdr.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        let expected = format!(
            "header line too long: scanned {} bytes without CRLF (capacity {})",
            size, size
        );
        assert_eq!(err.to_string(), expected);
    }

    #[tokio::test]
    async fn chunked_reader_errors_on_truncated_header() {
        let enc = b"10".to_vec();
        let r = MemReader::new(enc);
        let mut rdr = ChunkedReader::data_only(r);
        let mut out = Vec::new();
        let err = rdr.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(err.to_string(), "unexpected EOF");
    }

    #[tokio::test]
    async fn chunked_reader_errors_on_chunk_extension_length() {
        let enc = b"1a;foo=bar\r\n".to_vec();
        let r = MemReader::new(enc);
        let mut rdr = ChunkedReader::data_only(r);
        let mut out = Vec::new();
        let err = rdr.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "invalid chunk length: \"1a;foo=bar\"",);
    }

    #[tokio::test]
    async fn chunked_reader_full_roundtrip_including_headers_multi_chunk_small_buffer() {
        let data: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let enc = encode_with(MemReader::new(data.clone())).await;
        let mut rdr = ChunkedReader::new(MemReader::new(enc.clone()));
        let mut out = Vec::new();
        let mut tmp = [0u8; 3];
        loop {
            let n = AsyncReadExt::read(&mut rdr, &mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(out, enc);
    }

    #[tokio::test]
    async fn chunked_reader_data_only_drops_trailers() {
        let enc = b"5\r\nhello\r\n0\r\nx-checksum: abc123\r\n\r\n".to_vec();
        let mut rdr = ChunkedReader::data_only(MemReader::new(enc));
        let mut out = Vec::new();
        rdr.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello");
    }

    #[tokio::test]
    async fn chunked_reader_normalized_chunked_drops_trailers() {
        let enc = b"5\r\nhello\r\n0\r\nx-checksum: abc123\r\nfoo: bar\r\n\r\n".to_vec();
        let mut rdr = ChunkedReader::new(MemReader::new(enc));
        let mut out = Vec::new();
        rdr.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"5\r\nhello\r\n0\r\n\r\n");
    }

    #[tokio::test]
    async fn chunked_reader_data_only_preserves_next_message_when_crlf_split_across_fill_buf() {
        use super::buf_reader::BufReader;

        let enc =
            b"5\r\nhello\r\n0\r\nx-checksum: abc123\r\n\r\nGET /next HTTP/1.1\r\nHost: x\r\n\r\n"
                .to_vec();
        let mut rdr = ChunkedReader::data_only(BufReader::new(MemReader::new(enc), 1));
        let mut out = Vec::new();
        rdr.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello");

        let mut inner = rdr.into_inner();
        let mut remaining = Vec::new();
        inner.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, b"GET /next HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[tokio::test]
    async fn chunked_reader_normalized_preserves_next_message_when_crlf_split_across_fill_buf() {
        use super::buf_reader::BufReader;

        let enc = b"5\r\nhello\r\n0\r\nx-checksum: abc123\r\n\r\nHTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec();
        let mut rdr = ChunkedReader::new(BufReader::new(MemReader::new(enc), 1));
        let mut out = Vec::new();
        rdr.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"5\r\nhello\r\n0\r\n\r\n");

        let mut inner = rdr.into_inner();
        let mut remaining = Vec::new();
        inner.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(
            remaining,
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn limited_reader_propagates_inner_errors() {
        let inner = ErrorReader;
        let mut limited = LimitedReader::new(inner, 10);
        let mut out = Vec::new();
        let err = AsyncReadExt::read_to_end(&mut limited, &mut out)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "inner failure");
    }

    #[tokio::test]
    async fn chunked_writer_propagates_error_from_inner() {
        let mut w = ChunkedWriter::new(ErrorReader);
        let mut out = Vec::new();
        let err = w.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "inner failure");
    }

    #[tokio::test]
    async fn chunked_writer_no_uninitialized_bytes_on_error() {
        // Verify that when inner reader returns error, no uninitialized bytes are exposed
        let mut w = ChunkedWriter::new(ErrorReader);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf_space = [0xffu8; 64]; // fill with sentinel
        let mut rb = ReadBuf::new(&mut buf_space);
        let result = Pin::new(&mut w).poll_read(&mut cx, &mut rb);
        match result {
            Poll::Ready(Err(_)) => {
                // No bytes should be filled on error
                assert_eq!(rb.filled().len(), 0);
            }
            _ => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn chunked_writer_no_uninitialized_bytes_on_pending() {
        // Verify that when inner reader returns Pending, buffer is properly truncated
        let data = vec![1u8; 100];
        let mut w = ChunkedWriter::new(PendingOnceReader::new(data));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf_space = [0xffu8; 64];
        let mut rb = ReadBuf::new(&mut buf_space);

        // First poll should be Pending
        match Pin::new(&mut w).poll_read(&mut cx, &mut rb) {
            Poll::Pending => {
                // No bytes should be filled on Pending
                assert_eq!(rb.filled().len(), 0);
            }
            _ => panic!("expected Pending on first poll"),
        }
    }

    #[tokio::test]
    async fn buf_reader_no_uninitialized_bytes_on_error() {
        use super::buf_reader::BufReader;
        use tokio::io::AsyncBufReadExt;

        let mut reader = BufReader::new(ErrorReader, 64);
        let err = reader.fill_buf().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "inner failure");
    }

    #[tokio::test]
    async fn buf_reader_no_uninitialized_bytes_on_pending() {
        use super::buf_reader::BufReader;
        use tokio::io::AsyncBufRead;

        let data = vec![1u8; 100];
        let mut reader = BufReader::new(PendingOnceReader::new(data), 64);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll should be Pending
        match Pin::new(&mut reader).poll_fill_buf(&mut cx) {
            Poll::Pending => {
                // Buffer should still be empty after Pending
                assert_eq!(reader.buffer().len(), 0);
            }
            _ => panic!("expected Pending on first poll"),
        }
    }

    #[tokio::test]
    async fn buf_reader_preserves_data_on_partial_read() {
        use super::buf_reader::BufReader;
        use tokio::io::AsyncBufReadExt;

        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut reader = BufReader::new(MemReader::new(data.clone()), 64);

        // Fill buffer
        let buf = reader.fill_buf().await.unwrap();
        assert_eq!(buf, &data[..]);

        // Consume only part of it
        reader.consume(3);
        assert_eq!(reader.buffer(), &[4u8, 5, 6, 7, 8, 9, 10]);

        // Consume more
        reader.consume(4);
        assert_eq!(reader.buffer(), &[8u8, 9, 10]);
    }

    #[tokio::test]
    async fn buf_reader_repeated_single_byte_consume_preserves_remaining_bytes() {
        use super::buf_reader::BufReader;
        use tokio::io::AsyncBufReadExt;

        let data = b"abcdef".to_vec();
        let mut reader = BufReader::new(MemReader::new(data), 64);

        assert_eq!(reader.fill_buf().await.unwrap(), b"abcdef");
        reader.consume(1);
        assert_eq!(reader.fill_buf().await.unwrap(), b"bcdef");
        reader.consume(1);
        assert_eq!(reader.fill_buf().await.unwrap(), b"cdef");
        reader.consume(1);
        assert_eq!(reader.fill_buf().await.unwrap(), b"def");
        reader.consume(1);
        assert_eq!(reader.fill_buf().await.unwrap(), b"ef");
        reader.consume(1);
        assert_eq!(reader.fill_buf().await.unwrap(), b"f");
        reader.consume(1);
        assert_eq!(reader.fill_buf().await.unwrap(), b"");
    }

    #[tokio::test]
    async fn buf_reader_capacity_and_buffer() {
        use super::buf_reader::BufReader;

        let data = vec![1u8; 100];
        let reader = BufReader::new(MemReader::new(data), 32);

        assert_eq!(reader.capacity(), 32);
        assert_eq!(reader.buffer().len(), 0);
    }

    #[tokio::test]
    async fn chunked_writer_empty_input() {
        let data: Vec<u8> = vec![];
        let enc = encode_with(MemReader::new(data.clone())).await;
        assert_eq!(enc, b"0\r\n\r\n");
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_writer_single_byte() {
        let data = vec![42u8];
        let enc = encode_with(MemReader::new(data.clone())).await;
        assert!(enc.starts_with(b"1\r\n"));
        assert!(enc.ends_with(b"0\r\n\r\n"));
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_writer_exactly_max_data_size() {
        // Test exactly 4096 bytes (MAX_DATA_SIZE)
        let data = vec![0xAB_u8; 4096];
        let enc = encode_with(MemReader::new(data.clone())).await;
        // Should produce "1000\r\n" + 4096 bytes + "\r\n0\r\n\r\n"
        assert!(enc.starts_with(b"1000\r\n"));
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_reader_multiple_chunks_data_only() {
        // Create multi-chunk encoded data
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let enc = encode_with(MemReader::new(data.clone())).await;

        // Decode with data_only mode
        let mut rdr = ChunkedReader::data_only(MemReader::new(enc));
        let mut out = Vec::new();
        rdr.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn limited_reader_exact_boundary() {
        // Test when limit exactly matches source length
        let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let inner = MemReader::new(data.clone());
        let mut limited = LimitedReader::new(inner, 64);
        let mut out = Vec::new();
        AsyncReadExt::read_to_end(&mut limited, &mut out)
            .await
            .unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn chunked_writer_buffer_reuse() {
        // Verify buffer is properly reused across multiple reads
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let mut w = ChunkedWriter::new(MemReader::new(data.clone()));
        let mut enc = Vec::new();
        let mut tmp = [0u8; 100]; // Small buffer to force multiple reads
        loop {
            let n = AsyncReadExt::read(&mut w, &mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            enc.extend_from_slice(&tmp[..n]);
        }
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_reader_cleaning_state() {
        // Test the cleaning state transition after reading a chunk
        let data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let enc = encode_with(MemReader::new(data.clone())).await;

        // Use data_only mode to verify cleaning state works correctly
        let mut rdr = ChunkedReader::data_only(MemReader::new(enc));
        let mut buf = [0u8; 10];
        let mut total_read = 0;

        // Read in small chunks to exercise cleaning state
        while total_read < data.len() {
            let n = AsyncReadExt::read(&mut rdr, &mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total_read += n;
        }
        assert_eq!(total_read, data.len());
    }

    #[tokio::test]
    async fn buf_reader_poll_read_bypass() {
        use super::buf_reader::BufReader;

        // When buffer is empty, poll_read should bypass directly to inner
        let data = vec![1u8, 2, 3, 4, 5];
        let mut reader = BufReader::new(MemReader::new(data.clone()), 64);

        // Read directly without fill_buf
        let mut buf = [0u8; 5];
        let n = AsyncReadExt::read(&mut reader, &mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], &data[..]);
    }

    #[tokio::test]
    async fn buf_reader_reads_from_buffer_first() {
        use super::buf_reader::BufReader;
        use tokio::io::AsyncBufReadExt;

        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut reader = BufReader::new(MemReader::new(data.clone()), 64);

        // Fill buffer first
        reader.fill_buf().await.unwrap();

        // Now read should come from buffer
        let mut buf = [0u8; 3];
        let n = AsyncReadExt::read(&mut reader, &mut buf).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], &[1u8, 2, 3]);

        // Buffer should have remaining data
        assert_eq!(reader.buffer(), &[4u8, 5, 6, 7, 8, 9, 10]);
    }

    #[tokio::test]
    async fn chunked_writer_out_buffer_zero_remaining() {
        // Test when out buffer has zero remaining
        let data = vec![1u8; 100];
        let mut w = ChunkedWriter::new(MemReader::new(data));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf_space = [0u8; 0]; // Zero-length buffer
        let mut rb = ReadBuf::new(&mut buf_space);

        // Should return Ready(Ok(())) immediately
        match Pin::new(&mut w).poll_read(&mut cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                assert_eq!(rb.filled().len(), 0);
            }
            _ => panic!("expected Ready(Ok(())) with zero-length buffer"),
        }
    }
}
