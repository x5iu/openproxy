# Review Checklist

## Contents

- Rust safety and reliability
- HTTP proxy parsing and forwarding
- LLM provider auth and credential isolation
- Supply chain and CI checks
- Coverage expectations

## Rust safety and reliability

- Flag new `unsafe` unless the code proves memory safety and the reason is performance-critical.
- Flag `unwrap`, `expect`, `panic!`, and `todo!` on untrusted or network-driven paths.
- Check for blocking work in async request paths.
  This repository already executes shell commands for dynamic auth; any expansion of that path needs extra scrutiny for latency and DoS risk.
- Check for locks held across awaits or network I/O.
- Check for spawned tasks that can outlive config or connection state unsafely.
- Check for `Command`, `sh -c`, file I/O, env access, or path resolution changes.
- Check for secret material in logs, errors, metrics, or debug assertions.
- Check `Cargo.toml` and `Cargo.lock` changes for risky new dependencies, wide feature enables, or crypto/TLS changes.

## HTTP proxy parsing and forwarding

- Confirm Host and path matching still follows documented semantics.
- Confirm auth is extracted from the right place for each protocol:
  `Authorization`, `Proxy-Authorization`, provider-specific headers, or query key.
- Confirm all client auth headers are stripped before upstream forwarding for authenticating providers.
- Confirm `forward` remains the only transparent pass-through provider.
- Confirm request smuggling protections remain intact.
- Confirm header-size enforcement still applies to incoming HTTP/1.1 parsing.
- Confirm HTTP/2 request rebuilding does not duplicate forbidden or transformed headers.
- Confirm H2 to H1 fallback preserves:
  selected provider
  path rewrite
  auth filtering
  extra-header transform
  framing and body integrity
  stripping of client-supplied `Content-Length`/`Transfer-Encoding`
  stripping of `TE` / `Trailer`
  draining and dropping of request/response trailers rather than forwarding them
- Confirm CONNECT still validates target and only works when enabled.
- Confirm WebSocket upgrade code preserves handshake requirements without leaking client auth upstream.

## LLM provider auth and credential isolation

### OpenAI

- Client `Authorization` must authenticate the proxy, not pass through upstream.
- Dynamic `api_key: $(...)` must still emit exactly one upstream bearer token.
- Dynamic auth failures should produce controlled proxy errors.

### Gemini

- `x-goog-api-key` and query-key handling must not leave duplicate auth credentials upstream.
- Host or path rewrite changes must not desynchronize provider selection from auth filtering.

### Anthropic

- Standard mode and OAuth mode must stay distinct.
- OAuth mode must use `Authorization: Bearer ...` and the required `anthropic-beta` value.
- Existing beta headers must be merged or transformed safely, not duplicated unsafely.
- Standard mode must not accidentally inherit OAuth-only headers.

### Forward provider

- Treat any change that adds auth injection, auth inheritance, or header filtering to `forward` as high risk.
- Transparent forwarding must not be mistaken for secure-by-default behavior.

## Supply chain and CI checks

Run or verify at minimum:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --lib --verbose
cargo audit
```

Consider `cargo build --release` when the change affects startup, TLS, features, workflows, or build packaging.

When reviewing workflow or release changes, inspect:

- `.github/workflows/security.yml`
- `.github/workflows/e2e.yml`
- `.github/workflows/release.yml`
- `.github/workflows/docker-publish.yml`
- `Dockerfile`

Flag any change that weakens:

- security scanning scope
- secret scanning depth
- SARIF upload paths
- release provenance
- dependency pinning
- container hardening

## Coverage expectations

Treat missing tests as findings when the change alters behavior, not just refactoring internals.

Require targeted unit coverage for:

- parser and header-filter logic in `src/http/`
- selection and config semantics in `src/lib.rs`
- auth behavior and dynamic commands in `src/provider/`
- protocol bridging in `src/worker/` and `src/h2client/`

Require CI E2E mapping for:

- auth filtering and auth-selection behavior
- path rewrite and provider priority behavior
- CONNECT, WebSocket, H2 upstream, or H2 fallback behavior
- dynamic API key, OAuth, health-check auth, reload, and hot-upgrade behavior

Use these heuristics:

- If the diff changes a request or response header, expect at least one test that inspects headers.
- If the diff changes selection logic, expect at least one test that distinguishes similar providers.
- If the diff changes fallback or cross-protocol paths, expect coverage on both sides of the bridge.
- If the diff changes command execution or secret handling, expect explicit negative tests for failure, timeout, or injection.

## Review output requirements

- Findings come first, ordered by severity.
- Every finding states the concrete risk:
  auth bypass
  credential leak
  parsing ambiguity
  request smuggling
  SSRF or tunnel abuse
  command injection
  secret exposure
  denial of service
  stale config or upgrade regression
- Include exact file and line references when possible.
- State which checks were run and which could not be run.
- State which unit tests exist, which are missing, and which CI E2E suites should cover the change.
