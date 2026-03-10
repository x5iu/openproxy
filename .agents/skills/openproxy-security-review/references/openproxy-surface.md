# OpenProxy Review Surface

Use this file when you need the project-specific security model instead of generic Rust guidance.

## Module Map

- `src/http/mod.rs`
  HTTP/1.1 parsing, header filtering, host extraction, auth extraction, WebSocket upgrade detection, request and response body framing.
- `src/http/reader/mod.rs`
  Chunked decoding and bounded body readers. Relevant for body truncation, framing ambiguity, and parser resource limits.
- `src/worker/mod.rs`
  Main request routing path for HTTP/1.1 and HTTP/2, auth-during-selection, H2 to H1 fallback, CONNECT tunneling, WebSocket proxying, and upstream request rebuilding.
- `src/provider/mod.rs`
  Provider-specific auth behavior for `openai`, `gemini`, `anthropic`, and `forward`; dynamic `api_key: $(...)`; extra header transformation; health check request generation.
- `src/lib.rs`
  Config loading, YAML merge handling, provider construction, health-check scheduling, listener setup, weighted and priority selection, fallback semantics, graceful shutdown plumbing.
- `src/h2client/mod.rs`
  Upstream H2 pool and ALPN-based fallback to HTTP/1.1.
- `src/websocket/mod.rs`
  WebSocket handshake validation and bidirectional stream proxying.
- `src/main.rs`
  CLI entrypoint, PID file behavior, SIGHUP reload, SIGUSR2 hot-upgrade, and current executable path handling.

## Current Security-Critical Invariants

### HTTP parsing and filtering

- Reject duplicate `Content-Length`.
- Reject duplicate `Transfer-Encoding`.
- Reject requests that contain both `Content-Length` and `Transfer-Encoding: chunked`.
- Enforce `http_max_header_size`, clamped in config to `[1024, 1048576]`.
- Treat missing or empty `Host` as invalid for HTTP/1.1 routing.
- Filter auth headers based on all matching providers, not only the final selected provider.
- Always strip all `Proxy-Authorization` headers before forwarding upstream.
- Filter extra headers that will be transformed upstream, such as `anthropic-beta`.

### Provider selection and auth

- Selection order is: match host and optional path prefix, keep healthy providers, authenticate, prefer non-fallback, keep highest priority tier, then apply weight.
- `select_provider_with_auth` and `select_provider_with_auth_ignoring_health` in `src/lib.rs` define the 401 versus 404 split.
- `forward` is intentionally transparent and must not inherit top-level or provider-level `auth_keys`.
- Auth selection must not be re-done later using upstream host or rewritten path.

### Upstream credential handling

- Client credentials must not leak to upstream for `openai`, `gemini`, or `anthropic`.
- Dynamic `api_key: $(...)` is supported in practice for OpenAI and Anthropic paths and runs per request, including health checks and WebSocket upgrade.
- Dynamic auth output is trimmed and rejected if it contains CR, LF, or NUL.
- Dynamic auth failure should surface as a proxy failure, not a panic and not a leaked stderr blob.

### Protocol behaviors

- CONNECT is opt-in via `connect_tunnel_enabled`.
- CONNECT validates requested port against provider port when the client supplied a port.
- CONNECT may forward preread bytes, including TLS ClientHello.
- H2 upstream is attempted only over TLS with ALPN `h2`; otherwise fallback is HTTP/1.1.
- H2 to H1 fallback must preserve auth filtering and rewritten path, rebuild HTTP/1.1 framing without trusting client-supplied `Content-Length` or `Transfer-Encoding`, and does not forward request trailers on the fallback path.
- WebSocket is supported in HTTP/1.1 upgrade flow and H2 extended CONNECT flow.

### Reload and upgrade

- The worker intentionally drops read locks before network I/O to avoid starving config reload.
- SIGHUP replaces config and broadcasts shutdown to long-lived tasks.
- SIGUSR2 hot-upgrade respawns the binary with the same args and then performs graceful shutdown.
- Linux hot-upgrade resolves `current_exe()` paths ending with ` (deleted)`.

## Review Questions By File Area

### `src/http/mod.rs`

- Does the change widen accepted syntax for untrusted requests?
- Are filtered headers still removed in all matching-provider cases?
- Can duplicate or conflicting framing headers now pass?
- Does any new parsing branch create an out-of-bounds or unchecked UTF-8 risk?

### `src/worker/mod.rs`

- Is auth extracted once and reused consistently?
- Can H2 fallback, CONNECT, or WebSocket bypass auth or header filtering?
- Are locks dropped before connects, handshakes, or body proxying?
- Can provider reselection happen after auth succeeds?
- Does `forward` remain transparent without accidentally becoming privileged?

### `src/provider/mod.rs`

- Does provider auth still use constant-time key comparison where relevant?
- Can a new auth mode inject arbitrary header bytes upstream?
- Does any command execution path become slower, unbounded, or injectable?
- Are provider-specific headers added exactly once and filtered from client input first?

### `src/lib.rs`

- Do priority, weight, and fallback semantics still match the documented order?
- Does config loading preserve secret handling and safe defaults?
- Do YAML merges or provider expansions create duplicate or conflicting providers?
- Do listener and health-check changes alter exposed attack surface?

### `src/main.rs`

- Can reload or hot-upgrade spawn the wrong binary or lose PID tracking?
- Are config reload errors surfaced safely?
- Does any new signal path create privilege or lifecycle confusion?

## Existing Unit Test Hotspots

- `src/http/mod.rs`
  Smuggling and parsing rejection tests, proxy-auth filtering, Host handling.
- `src/provider/mod.rs`
  Dynamic auth command execution, header injection rejection, timeout behavior, Anthropic OAuth behavior, forward provider auth semantics.
- `src/lib.rs`
  Fallback, priority, weighted selection, auth-during-selection, YAML merge behavior, header-size bounds.
- `src/worker/mod.rs`
  H2 fallback request rebuilding and framing distrust (including stripped client `Content-Length`/`Transfer-Encoding` cases), auth-header filtering on H2 upstream, WebSocket request rewrite, auth-header collection.
- `src/h2client/mod.rs`
  ALPN fallback behavior and H2 pool behavior.

## E2E Mapping

Do not run these locally. Use them to judge whether CI coverage is sufficient.

- Auth filtering and client-credential isolation
  `e2e/test_proxy_authorization_filtering.py`
  `e2e/test_h2_auth_header_filtering.py`
  `e2e/test_duplicate_extra_header_filtering.py`
  `e2e/test_no_auth_keys_filtering.py`
- Auth selection, routing, and provider choice
  `e2e/test_auth_selection.py`
  `e2e/test_rewrite_auth_selection.py`
  `e2e/test_provider_priority.py`
  `e2e/test_host_path.py`
- Protocol behavior
  `e2e/test_http.py`
  `e2e/test_https.py`
  `e2e/test_h2_upstream.py`
  `e2e/test_h2_large_body.py`
  `e2e/test_h2_h1_fallback.py`
  `e2e/test_h2_h1_fallback_framing.py`
  `e2e/test_connect_tunnel.py`
  `e2e/test_websocket.py`
  `e2e/test_openai_realtime.py`
- Dynamic credentials, reload, and health checks
  `e2e/test_openai_dynamic_api_key.py`
  `e2e/test_anthropic_oauth.py`
  `e2e/test_health_check_auth.py`
  `e2e/test_sighup_reload.py`
  `e2e/test_hot_upgrade.py`
- Strict parsing
  `e2e/test_strict_http_parsing.py`

## CI Expectations

- `.github/workflows/security.yml`
  Cargo Audit, CodeQL, Gitleaks, Semgrep, Scorecard, and Trivy.
- `.github/workflows/e2e.yml`
  `cargo test --lib --verbose` locally mirrored in CI, followed by secret-backed E2E coverage.

If a change affects security posture but does not map cleanly to one of the suites above, call that out as a coverage gap.
