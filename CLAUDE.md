# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build
cargo build --release

# Run all tests
cargo test

# Run a specific test
cargo test test_name

# Lint and format
cargo clippy
cargo fmt

# Start the server
./target/release/openproxy start -c config.yml
./target/release/openproxy start -c config.yml --enable-health-check
./target/release/openproxy start -c config.yml -p /var/run/openproxy.pid
```

## E2E Tests

```bash
cd e2e
pip install openai pydantic "httpx[http2]" websockets websocket-client pyyaml

# Run individual test suites
python test_https.py
python test_http.py
python test_websocket.py
python test_host_path.py
python test_anthropic_oauth.py
```

## Architecture

OpenProxy is a high-performance LLM proxy server that routes requests to multiple providers (OpenAI, Gemini, Anthropic) based on the `Host` header.

### Core Modules

- **`src/lib.rs`** - Configuration loading, provider selection with weighted load balancing, TLS setup, global `Program` state
- **`src/worker/mod.rs`** - Request handling for HTTP/1.1 and HTTP/2, WebSocket proxying, `UpstreamInfo` struct for provider details
- **`src/provider/mod.rs`** - Provider trait and implementations (OpenAI, Gemini, Anthropic), authentication handling
- **`src/http/mod.rs`** - HTTP parsing, header manipulation, `Payload` struct with `next_block()` state machine for streaming
- **`src/executor/mod.rs`** - Connection pooling (`Pool<K, V>`) and health check execution
- **`src/h2client/mod.rs`** - HTTP/2 client connections to upstream, TLS connector, connection pooling for H2
- **`src/websocket/mod.rs`** - WebSocket upgrade detection and bidirectional proxying

### Request Flow

1. Client connects via TCP (HTTP or HTTPS)
2. For HTTPS: TLS handshake with ALPN negotiation (h2 or http/1.1)
3. `Executor` spawns a `Worker` to handle the connection
4. Worker reads the request, extracts `Host` header
5. `Program::select_provider()` finds matching provider(s) by host, applies weighted selection if multiple
6. Worker proxies request to provider, streams response back
7. For WebSocket: detects upgrade headers, establishes bidirectional tunnel

### Provider Trait

The `Provider` trait defines how each LLM provider handles authentication and headers:
- `auth_header()` / `auth_header_key()` - Static authentication headers
- `uses_dynamic_auth()` / `get_dynamic_auth_header()` - Dynamic auth (e.g., OAuth with `$(command)` pattern)
- `extra_headers()` / `transform_extra_header()` - Additional headers to filter and transform (e.g., `anthropic-beta` for OAuth)

### HTTP Header Processing (HTTP/1.1)

The `Payload` struct in `http/mod.rs` uses a state machine (`ReadState`) to stream request/response data:
- Headers are parsed and certain headers are filtered (`Host`, `Connection`, auth headers, extra headers)
- `header_chunks: Vec<Range<usize>>` stores non-filtered header ranges
- `split_header_chunks()` computes which parts of the header buffer to send upstream
- Provider-specific headers are injected during streaming via `next_block()`

### HTTP/2 Header Processing

For HTTP/2 (`worker/mod.rs`):
- `UpstreamInfo` struct pre-computes transformed headers before sending upstream
- `extra_header_keys` and `extra_headers_transformed` hold header transformations
- Headers are filtered and replaced during request building in `proxy_h2()` and `proxy_h1()` (H1 fallback)

### Provider Selection

Providers are matched by the `Host` header from the client request. When multiple healthy providers match:
- Weighted random selection using `WeightedIndex`
- Health checks run at configurable intervals
- Unhealthy providers are excluded from selection

### Protocol Support

- **HTTP/1.1**: Plain HTTP and HTTPS with keep-alive
- **HTTP/2**: Full multiplexing support, Extended CONNECT for WebSocket (RFC 8441), automatic H1 fallback for non-TLS upstreams
- **WebSocket**: Transparent proxying for both HTTP/1.1 upgrade and HTTP/2 CONNECT

### Configuration

YAML-based config with hot-reload via SIGHUP. Key fields:
- `https_port` / `http_port`: At least one required
- `https_bind_address` / `http_bind_address`: Bind address for each listener (default: 0.0.0.0)
- `cert_file` / `private_key_file`: Required for HTTPS
- `providers[]`: Type, host (for routing), endpoint (actual backend), api_key, weight, tls
- `auth_keys`: Global authentication keys

### Signal Handling

- **SIGTERM/SIGINT**: Graceful shutdown
- **SIGHUP**: Reload configuration without restart
- **SIGUSR2**: Hot upgrade (spawn new process, then graceful shutdown)

### Error Handling

Custom `Error` enum in `lib.rs` with variants:
- `IO`, `TLS`, `H2` - Protocol errors
- `HeaderTooLarge`, `InvalidHeader` - Parsing errors
- `NoProviderFound` - Routing errors
- `DynamicAuthFailed` - OAuth/dynamic authentication errors
