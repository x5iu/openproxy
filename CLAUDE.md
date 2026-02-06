# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build
cargo build --release

# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run a specific test
cargo test test_name

# Lint and format
cargo clippy
cargo fmt

# Start the server
./target/release/openproxy start -c config.yml
./target/release/openproxy start -c config.yml -p /var/run/openproxy.pid
```

## E2E Tests

E2E tests are Python scripts in `e2e/`. There are two patterns:

**CI-dependent tests** rely on the proxy instance started by `.github/workflows/e2e.yml` (with real API keys from GitHub Secrets and multiple Python echo servers on ports 9000-9007):
```bash
python test_https.py
python test_http.py
python test_websocket.py
python test_host_path.py
python test_anthropic_oauth.py
python test_anthropic_api.py
python test_auth_selection.py
python test_rewrite_auth_selection.py
python test_connect_tunnel.py
python test_forward.py
python test_h2_upstream.py
python test_h2_h1_fallback.py
python test_h2_large_body.py
python test_openai_realtime.py
```

**Self-contained tests** start their own openproxy instance with a temporary config, certs, and echo server. These can run locally with just the compiled binary:
```bash
python test_hot_upgrade.py
python test_health_check_auth.py
python test_no_auth_keys_filtering.py
python test_sighup_reload.py
```

Dependencies: `pip install openai pydantic "httpx[http2]" websockets websocket-client pyyaml anthropic`

Self-contained tests find the binary via `OPENPROXY_BINARY` env var or auto-detect from `target/release/` or `target/debug/`.

## Architecture

OpenProxy is a high-performance LLM proxy server that routes requests to multiple providers (OpenAI, Gemini, Anthropic, Forward) based on the `Host` header.

### Core Modules

- **`src/lib.rs`** — Configuration loading (`Config` / `ProviderConfig` structs), provider selection with weighted load balancing, TLS setup, global `Program` state (behind `Arc<RwLock<Program>>`)
- **`src/worker/mod.rs`** — Request handling for HTTP/1.1 and HTTP/2, WebSocket proxying, `UpstreamInfo` struct for pre-computed provider details
- **`src/provider/mod.rs`** — `Provider` trait and implementations (OpenAI, Gemini, Anthropic, Forward), authentication handling
- **`src/http/mod.rs`** — HTTP/1.1 parsing, header filtering, `Payload` struct with `ReadState` state machine for streaming
- **`src/http/reader/mod.rs`** — Streaming helpers: `LimitedReader` (Content-Length), `ChunkedReader`/`ChunkedWriter` (Transfer-Encoding: chunked)
- **`src/executor/mod.rs`** — Connection pooling (`Pool<K, V>`) and health check execution
- **`src/h2client/mod.rs`** — HTTP/2 client connections to upstream, TLS connector, connection pooling for H2
- **`src/websocket/mod.rs`** — WebSocket upgrade detection and bidirectional proxying

### Request Flow

1. Client connects via TCP (HTTP or HTTPS)
2. For HTTPS: TLS handshake with ALPN negotiation (h2 or http/1.1)
3. `Executor` spawns a `Worker` to handle the connection
4. Worker reads the request, extracts `Host` header
5. `Program::select_provider()` finds matching provider(s) by host + optional path prefix, applies weighted selection if multiple
6. Worker proxies request to provider, streams response back
7. For WebSocket: detects upgrade headers, establishes bidirectional tunnel

### Header Processing: HTTP/1.1 vs HTTP/2

This is the most architecturally important distinction in the codebase. The two paths handle header filtering and injection differently due to protocol constraints.

**HTTP/1.1 (two-phase: parse-time filtering + streaming injection)**

In `http/mod.rs`, `Payload::read_from()` performs parsing:
1. Collects auth header keys from ALL matching providers (not just the selected one) to prevent credential leakage
2. Identifies filtered header byte ranges (Host, Connection, auth, extra headers)
3. `split_header_chunks()` computes non-filtered header ranges stored as `header_chunks: Vec<Range<usize>>`

Then `next_block()` uses a `ReadState` state machine to stream the rewritten request:
- `Start` → outputs header chunks (the non-filtered parts of the original header buffer)
- `HostHeader` → outputs upstream host header
- `AuthHeader` → outputs provider auth header + transformed extra headers
- `ConnectionHeader` → outputs `Connection: keep-alive\r\n`
- `FinishHeader` → outputs final `\r\n`
- `ReadBody` / `UnreadBody` → streams body

**HTTP/2 (pre-computed in UpstreamInfo)**

In `worker/mod.rs`, the `UpstreamInfo` struct pre-computes all header transformations before building the upstream request:
- `auth_header_keys: Vec<String>` — headers to strip from client request
- `auth_header: Option<String>` — provider auth to inject
- `extra_header_keys` / `extra_headers_transformed` — extra headers to filter and replace
- `proxy_h2()` builds the upstream request by iterating client headers, skipping filtered ones, then adding pre-computed replacements

**Key invariant**: Both paths must filter the same headers. Auth header keys are collected unconditionally from `provider.auth_header_keys()` (not gated by `has_auth_keys()`).

### Provider Trait

The `Provider` trait (`src/provider/mod.rs`) defines how each LLM provider handles authentication and headers:

- `auth_header()` / `auth_header_key()` — Static auth header value and key name. The key (e.g., `"Authorization: "`) determines what to filter from client requests. The value is what gets injected for upstream.
- `auth_header_keys()` — Returns all auth header key names to filter. Default impl delegates to `auth_header_key()`. Anthropic overrides to return both `X-API-Key: ` and `Authorization: `.
- `has_auth_keys()` — Whether client auth validation is needed (`!auth_keys.is_empty() || provider_auth_keys.is_some()`). This is for authentication gating only, NOT for header filtering.
- `authenticate_with_type()` — Returns the auth type used (e.g., `"x-api-key"`, `"bearer"`) so `get_upstream_auth_header()` can select the correct upstream auth format.
- `uses_dynamic_auth()` / `get_dynamic_auth_header()` — Dynamic auth via `$(command)` pattern (used for Anthropic OAuth).
- `extra_headers()` / `transform_extra_header()` — Additional headers to filter and transform (e.g., `anthropic-beta` for OAuth).

**Forward provider** is special: `auth_header_key()` returns `None`, so `auth_header_keys()` returns an empty vec — no client headers are filtered, enabling transparent proxying.

### Authentication: auth_keys vs provider_auth_keys

- `auth_keys: Arc<Vec<String>>` — Global keys shared across all providers via `Arc::clone()`
- `provider_auth_keys: Option<Vec<String>>` — Per-provider keys from `auth_keys` field in provider config
- Authentication checks both lists via `.chain()`: `auth_keys.iter().chain(provider_auth_keys.iter().flatten())`
- If both are empty (`has_auth_keys()` returns false), authentication is skipped entirely (open access)

### Provider Selection and Path Prefix

`Program::select_provider()` in `src/lib.rs` matches providers by host header. Provider `host` can include a path prefix (e.g., `"localhost:8080/v1"`), which is split by `http::split_host_path()`.

Path prefix matching requires the request path to start with the prefix AND the next character must be `/` or end-of-string (prevents `/v1` matching `/v10`).

When multiple healthy providers match:
- Non-fallback providers are preferred over fallback providers
- Among matches, weighted random selection using `WeightedIndex`
- Unhealthy providers (failed health checks) are excluded

### Configuration

YAML-based config with hot-reload via SIGHUP. Key fields:
- `https_port` / `http_port`: At least one required
- `https_bind_address` / `http_bind_address`: Bind address for each listener (default: 0.0.0.0)
- `cert_file` / `private_key_file`: Required for HTTPS
- `providers[]`: Type (openai, gemini, anthropic, forward), host (for routing), endpoint (actual backend), api_key, weight, tls, is_fallback
- `auth_keys`: Global authentication keys
- `health_check.enabled` / `health_check.interval`: Enable health checks and set interval (default: 60s)
- `http_max_header_size`: Maximum HTTP header size in bytes (default: 4096, min: 1024, max: 1MB)
- `connect_tunnel_enabled`: Enable HTTP CONNECT method for forward proxy tunnels

### Signal Handling

- **SIGTERM/SIGINT**: Graceful shutdown
- **SIGHUP**: Reload configuration without restart
- **SIGUSR2**: Hot upgrade (spawn new process, then graceful shutdown)

### Error Handling

Custom `Error` enum in `lib.rs` with variants:
- `IO`, `TLS`, `H2` — Protocol errors
- `HeaderTooLarge`, `InvalidHeader` — Parsing errors
- `NoProviderFound` — Routing errors
- `DynamicAuthFailed` — OAuth/dynamic authentication errors
