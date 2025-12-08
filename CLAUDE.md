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

# Run with verbose output
cargo test --lib --verbose

# Start the server
./target/release/openproxy start -c config.yml
./target/release/openproxy start -c config.yml --enable-health-check
```

## E2E Tests

```bash
cd e2e
pip install openai pydantic "httpx[http2]" websockets websocket-client

# Run individual test suites
python test_https.py
python test_http.py
python test_websocket.py
```

## Architecture

OpenProxy is a high-performance LLM proxy server that routes requests to multiple providers (OpenAI, Gemini, Anthropic) based on the `Host` header.

### Core Modules

- **`src/lib.rs`** - Configuration loading, provider selection with weighted load balancing, TLS setup
- **`src/worker/mod.rs`** - Request handling for HTTP/1.1 and HTTP/2, WebSocket proxying
- **`src/provider/mod.rs`** - Provider trait and implementations (OpenAI, Gemini, Anthropic)
- **`src/http/mod.rs`** - HTTP parsing, header manipulation, payload reading
- **`src/executor/mod.rs`** - Connection pooling and health check execution
- **`src/websocket/mod.rs`** - WebSocket upgrade detection and bidirectional proxying

### Request Flow

1. Client connects via TCP (HTTP or HTTPS)
2. For HTTPS: TLS handshake with ALPN negotiation (h2 or http/1.1)
3. `Executor` spawns a `Worker` to handle the connection
4. Worker reads the request, extracts `Host` header
5. `Program::select_provider()` finds matching provider(s) by host, applies weighted selection if multiple
6. Worker proxies request to provider, streams response back
7. For WebSocket: detects upgrade headers, establishes bidirectional tunnel

### Provider Selection

Providers are matched by the `Host` header from the client request. When multiple healthy providers match:
- Weighted random selection using `WeightedIndex`
- Health checks run at configurable intervals
- Unhealthy providers are excluded from selection

### Protocol Support

- **HTTP/1.1**: Plain HTTP and HTTPS with keep-alive
- **HTTP/2**: Full multiplexing support, Extended CONNECT for WebSocket (RFC 8441)
- **WebSocket**: Transparent proxying for both HTTP/1.1 upgrade and HTTP/2 CONNECT

### Configuration

YAML-based config with hot-reload via SIGHUP. Key fields:
- `https_port` / `http_port`: At least one required
- `cert_file` / `private_key_file`: Required for HTTPS
- `providers[]`: Type, host (for routing), endpoint (actual backend), api_key, weight, tls
- `auth_keys`: Global authentication keys
