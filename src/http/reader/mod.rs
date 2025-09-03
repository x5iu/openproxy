use std::io::{self};
use std::pin::{pin, Pin};
use std::task::{Context, Poll};

use super::CRLF;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, ReadBuf};

use buf_reader::BufReader;

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
            frame: Vec::with_capacity(Self::MAX_HEADER_SIZE + CRLF.len() + Self::MAX_DATA_SIZE + CRLF.len()),
            buf: Vec::with_capacity(Self::MAX_DATA_SIZE),
            pos: 0,
            finished: false,
        }
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
                // SAFETY: we extend the vector length to MAX_DATA_SIZE to obtain a writable buffer;
                // only the first `n` bytes returned by the inner reader are initialized and later read.
                // We never read uninitialized bytes.
                unsafe { this.buf.set_len(Self::MAX_DATA_SIZE); }
            }
            let n = {
                let mut rb = ReadBuf::new(&mut this.buf[..Self::MAX_DATA_SIZE]);
                let Poll::Ready(_) = pin!(&mut this.reader).poll_read(cx, &mut rb)? else {
                    return Poll::Pending;
                };
                rb.filled().len()
            };
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

pub struct ChunkedReader<R> {
    data_only: bool,
    reader: BufReader<R>,
    unread_chunk_length: usize,
    cleaning: bool,
    finished: bool,
}

impl<R: AsyncRead + Unpin + Send + Sync> ChunkedReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            data_only: false,
            reader: BufReader::new(reader, super::DEFAULT_BUFFER_SIZE),
            unread_chunk_length: 0,
            cleaning: false,
            finished: false,
        }
    }

    pub fn data_only(reader: R) -> ChunkedReader<R> {
        let mut reader = ChunkedReader::new(reader);
        reader.data_only = true;
        reader
    }

    fn internal_poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        #[inline]
        fn poll_find_next_crlf<R: AsyncRead + Unpin + Send + Sync>(
            reader: &mut BufReader<R>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<usize>> {
            #[inline]
            fn find_crlf(buffer: &[u8]) -> Option<usize> {
                buffer.windows(2).position(|window| window == CRLF)
            }
            let mut buffer = reader.buffer();
            if let Some(idx) = find_crlf(buffer) {
                return Poll::Ready(Ok(idx));
            }
            let capacity = reader.capacity();
            while buffer.len() < capacity {
                let Poll::Ready(new_buffer) = Pin::new(&mut *reader).poll_fill_buf(cx)? else {
                    return Poll::Pending;
                };
                buffer = new_buffer;
                if let Some(idx) = find_crlf(buffer) {
                    return Poll::Ready(Ok(idx));
                }
            }
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "header line too long: scanned {} bytes without CRLF (capacity {})",
                    buffer.len(),
                    capacity
                ),
            )))
        }
        if self.cleaning {
            if self.data_only {
                let buffer = if self.reader.buffer().len() < CRLF.len() {
                    let Poll::Ready(buffer) = Pin::new(&mut self.reader).poll_fill_buf(cx)? else {
                        return Poll::Pending;
                    };
                    buffer
                } else {
                    self.reader.buffer()
                };
                debug_assert_eq!(&buffer[..CRLF.len()], CRLF);
                self.reader.consume(CRLF.len());
            }
            self.cleaning = false;
        }
        if self.unread_chunk_length == 0 {
            if self.finished {
                return Poll::Ready(Ok(()));
            }
            let Poll::Ready(idx) = poll_find_next_crlf(&mut self.reader, cx)? else {
                return Poll::Pending;
            };
            let buffer = self.reader.buffer();
            #[cfg(debug_assertions)]
            log::info!(buffer:serde = buffer.to_vec(), index = idx; "read_chunk_header_line");
            self.unread_chunk_length = {
                let Ok(length_str) = std::str::from_utf8(&buffer[..idx]) else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "non-utf8 chunk length",
                    )));
                };
                let Ok(length) = usize::from_str_radix(length_str, 16) else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("invalid chunk length: \"{}\"", length_str),
                    )));
                };
                if length == 0 {
                    self.finished = true;
                }
                if self.data_only {
                    self.reader.consume(idx + CRLF.len());
                    length
                } else {
                    idx + CRLF.len() + length + CRLF.len()
                }
            };
        }
        let max = std::cmp::min(self.unread_chunk_length, buf.remaining());
        let mut real_buf = ReadBuf::new(&mut buf.initialize_unfilled()[..max]);
        let poll = pin!(&mut self.reader).poll_read(cx, &mut real_buf)?;
        let n = real_buf.filled().len();
        self.unread_chunk_length -= n;
        self.cleaning = self.unread_chunk_length == 0;
        buf.advance(n);
        poll.map(|_| Ok(()))
    }
}

impl<R: AsyncRead + Unpin + Send + Sync> AsyncRead for ChunkedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.internal_poll_read(cx, buf) {
            Poll::Ready(Err(e)) => {
                // This log is recorded to diagnose the `illegal chunk header` and `InvalidChunkLength` error.
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

    use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

    pub(crate) struct BufReader<R: ?Sized> {
        buf: Vec<u8>,
        inner: R,
    }

    impl<R> BufReader<R> {
        pub(crate) fn new(inner: R, size: usize) -> Self {
            let buf = Vec::with_capacity(size);
            Self { buf, inner }
        }

        pub(crate) fn capacity(&self) -> usize {
            self.buf.capacity()
        }

        pub(crate) fn buffer(&self) -> &[u8] {
            &self.buf[..]
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
            if self.buf.len() == 0 {
                return pin!(&mut self.inner).poll_read(cx, buf);
            }
            let mut real_buf = ReadBuf::new(buf.initialize_unfilled());
            #[allow(unused)]
            pin!(&self.buf[..]).poll_read(cx, &mut real_buf)?;
            let n = real_buf.filled().len();
            self.consume(n);
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl<R: AsyncRead + Unpin + Send + Sync> AsyncBufRead for BufReader<R> {
        fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let me = self.get_mut();
            let (len, cap) = (me.buf.len(), me.buf.capacity());
            if len < cap {
                unsafe {
                    me.buf.set_len(cap);
                    let mut buf = ReadBuf::new(&mut me.buf[len..cap]);
                    let poll = pin!(&mut me.inner).poll_read(cx, &mut buf)?;
                    let n = buf.filled().len();
                    me.buf.set_len(len + n);
                    if poll.is_pending() {
                        return Poll::Pending;
                    } else if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected EOF",
                        )));
                    }
                }
            }
            Poll::Ready(Ok(&me.buf[..]))
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            self.get_mut().buf.drain(..amt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ChunkedReader, ChunkedWriter};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

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
            Self { inner: MemReader::new(data), pending: true }
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
            Self { inner: MemReader::new(data), remaining: n }
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

    fn noop_waker() -> std::task::Waker {
        unsafe fn clone(_: *const ()) -> std::task::RawWaker { std::task::RawWaker::new(std::ptr::null(), &VTABLE) }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: std::task::RawWakerVTable = std::task::RawWakerVTable::new(clone, wake, wake_by_ref, drop);
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
            if n == 0 { break; }
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
        let mut enc = Vec::from(&rb.filled()[..]);
        let mut tmp = [0u8; 256];
        loop {
            let m = AsyncReadExt::read(&mut w, &mut tmp).await.unwrap();
            if m == 0 { break; }
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
        let mut enc = Vec::from(&rb.filled()[..]);
        let mut tmp = [0u8; 256];
        loop {
            let m = AsyncReadExt::read(&mut w, &mut tmp).await.unwrap();
            if m == 0 { break; }
            enc.extend_from_slice(&tmp[..m]);
        }
        let dec = decode_chunked(enc).await;
        assert_eq!(dec, data);
    }

    #[tokio::test]
    async fn chunked_reader_full_roundtrip_including_headers() {
        let data: Vec<u8> = (0..1234).map(|i| (i % 251) as u8).collect();
        let enc = encode_with(MemReader::new(data)).await;
        let mut rdr = ChunkedReader::new(MemReader::new(enc.clone()));
        let mut out = Vec::new();
        rdr.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, enc);
    }
}
