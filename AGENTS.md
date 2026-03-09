# Repository Guidelines

## Project Structure & Module Organization
`openproxy` is a Rust 2021 project centered in `src/`:
- `src/main.rs`: CLI entrypoint (`openproxy start -c ...`), PID file handling, and signal-driven reload/hot-upgrade.
- `src/lib.rs`: config loading, listener/runtime setup, provider construction, health-check wiring, and graceful shutdown.
- `src/http/` and `src/http/reader/`: HTTP/1.1 parsing, header filtering/rewriting, and chunked/body readers.
- `src/worker/`: request routing, provider selection, HTTP/1.1 and HTTP/2 proxy flows, CONNECT tunneling, and WebSocket upgrade handling.
- `src/provider/`: provider implementations for `openai`, `gemini`, `anthropic`, and `forward`.
- `src/h2client/`, `src/websocket/`, `src/executor/`: upstream HTTP/2 client/pool, WebSocket proxy helpers, and connection pooling/health checks.

Top-level support files:
- `README.md`: user-facing config and deployment documentation, including `forward` provider transparency/auth semantics and HTTP/2→HTTP/1.1 fallback framing behavior.
- `Dockerfile`: container image build.
- `.github/workflows/e2e.yml`: Rust unit tests plus secret-backed E2E coverage.
- `.github/workflows/security.yml`: cargo-audit, CodeQL, Gitleaks, Semgrep, Scorecard, and Trivy.
- `.github/workflows/release.yml` and `.github/workflows/docker-publish.yml`: tag/release automation and multi-arch image publishing.

End-to-end tests live in `e2e/` as `test_*.py` files, with helpers like `e2e/websocket_echo_server.py`.

## Build, Test, and Development Commands
- `cargo build --release`: build optimized binary (`target/release/openproxy`).
- `cargo run -- start -c config.yml`: run locally without a separate build step.
- `cargo test --lib --verbose`: run Rust unit/integration tests (CI baseline).
- `cargo test`: run all Rust tests.
- `cargo fmt --all` and `cargo clippy --all-targets --all-features`: formatting and lint checks before opening a PR.
- `docker build -t openproxy .`: build the local container image from `Dockerfile`.

For E2E tests:
- Do not run `e2e/test_*.py` locally.
- Validate E2E coverage through the PR's GitHub Actions `E2E Tests` workflow (`.github/workflows/e2e.yml`).
- If a change depends on provider secrets or real upstream behavior, assume CI is the source of truth.

## Coding Style & Naming Conventions
Follow standard Rust style (4-space indentation, `rustfmt` defaults). Use:
- `snake_case` for files, modules, functions, and variables.
- `PascalCase` for types/traits/enums.
- `UPPER_SNAKE_CASE` for constants/statics.

Keep protocol-specific changes scoped to the relevant module and prefer structured logging (`log` + `structured-logger`) over ad hoc prints. Parser/header changes usually belong in `src/http/`; routing, upstream selection, and proxying behavior belong in `src/worker/`; auth/provider-specific transformations belong in `src/provider/`.

## Testing Guidelines
Rust tests are colocated with code under `#[cfg(test)]`; async tests use `#[tokio::test]`. Prefer focused unit tests in the touched module, then run `cargo test --lib --verbose`.
E2E verification is CI-only: do not run the Python E2E suite locally; rely on the PR GitHub Actions runs instead.
Name E2E tests by behavior (`test_connect_tunnel.py`, `test_auth_selection.py`, `test_h2_h1_fallback.py`, `test_openai_dynamic_api_key.py`, etc.).

No explicit coverage threshold is enforced, but PRs should include:
- unit tests for parsing/routing/auth logic changes
- targeted E2E coverage for protocol, auth, reload, or hot-upgrade behavior changes
- for auth/header-filtering regressions, prefer focused E2E scripts in `e2e/` such as `test_proxy_authorization_filtering.py`, `test_h2_auth_header_filtering.py`, `test_duplicate_extra_header_filtering.py`, `test_no_auth_keys_filtering.py`, and `test_strict_http_parsing.py`; cover the HTTP/2 upstream forwarding path with Rust unit tests in `src/worker/mod.rs`
- for provider selection/path rewrite changes, look at `test_auth_selection.py`, `test_rewrite_auth_selection.py`, `test_provider_priority.py`, and `test_host_path.py`
- for protocol behavior changes, look at `test_http.py`, `test_https.py`, `test_h2_upstream.py`, `test_h2_large_body.py`, `test_h2_h1_fallback.py`, `test_h2_h1_fallback_framing.py`, `test_connect_tunnel.py`, and `test_websocket.py`
- for reload, hot-upgrade, or dynamic credential changes, look at `test_sighup_reload.py`, `test_hot_upgrade.py`, `test_openai_dynamic_api_key.py`, `test_anthropic_oauth.py`, and `test_health_check_auth.py`

## Commit & Pull Request Guidelines
Recent history follows Conventional Commits with optional scopes, for example `feat:`, `fix:`, `docs(readme):`, `feat(openai):`, `refactor:`, and `test:` (often with issue refs like `(#52)`).

PRs should be focused and include:
- clear summary and rationale
- linked issue(s), if applicable
- exact Rust test commands run locally and results
- expected GitHub Actions coverage for any affected E2E scenarios
- config/security impact notes (especially auth headers, API keys, TLS/cert behavior)
- release impact notes when touching packaging, Docker, or workflow files

Versioning note:
- Changing the version in `Cargo.toml` on `master` triggers the automated release workflow, which creates a git tag, release artifacts, and Docker image publishing. Treat version bumps as intentional release actions.
