# Repository Guidelines

## Project Structure & Module Organization
`openproxy` is a Rust 2021 project centered in `src/`:
- `src/main.rs`: CLI entrypoint (`openproxy start -c ...`) and signal handling.
- `src/lib.rs`: config loading, runtime wiring, provider selection, and shutdown flow.
- `src/http/`, `src/h2client/`, `src/websocket/`: protocol handling.
- `src/provider/`, `src/worker/`, `src/executor/`: routing, business logic, and async execution.

End-to-end tests live in `e2e/` as `test_*.py` files, with helpers like `e2e/websocket_echo_server.py`. CI/CD workflows are in `.github/workflows/` (notably `e2e.yml`, `security.yml`, and release workflows).

## Build, Test, and Development Commands
- `cargo build --release`: build optimized binary (`target/release/openproxy`).
- `cargo run -- start -c config.yml`: run locally without a separate build step.
- `cargo test --lib --verbose`: run Rust unit/integration tests (CI baseline).
- `cargo test`: run all Rust tests.
- `cargo fmt --all` and `cargo clippy --all-targets --all-features`: formatting and lint checks before opening a PR.

For E2E tests (Python 3.11 in CI):
- `pip install openai pydantic "httpx[http2]" "websockets==10.4" websocket-client pyyaml anthropic`
- `cd e2e && python test_https.py` (swap in other `test_*.py` as needed)

## Coding Style & Naming Conventions
Follow standard Rust style (4-space indentation, `rustfmt` defaults). Use:
- `snake_case` for files, modules, functions, and variables.
- `PascalCase` for types/traits/enums.
- `UPPER_SNAKE_CASE` for constants/statics.

Keep protocol-specific changes scoped to the relevant module and prefer structured logging (`log` + `structured-logger`) over ad hoc prints.

## Testing Guidelines
Rust tests are colocated with code under `#[cfg(test)]`; async tests use `#[tokio::test]`. Name E2E tests by behavior (`test_connect_tunnel.py`, `test_auth_selection.py`, etc.).

No explicit coverage threshold is enforced, but PRs should include:
- unit tests for parsing/routing/auth logic changes
- targeted E2E coverage for protocol, auth, reload, or hot-upgrade behavior changes

## Commit & Pull Request Guidelines
Recent history follows Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:` (often with issue refs like `(#52)`).

PRs should be focused and include:
- clear summary and rationale
- linked issue(s), if applicable
- exact test commands run and results
- config/security impact notes (especially auth headers, API keys, TLS/cert behavior)
