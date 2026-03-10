---
name: openproxy-security-review
description: Review code changes in the OpenProxy Rust HTTP proxy with a security-first mindset. Use when inspecting diffs, pull requests, or local edits that may affect HTTP parsing, header filtering or rewriting, authentication, provider selection, CONNECT tunneling, WebSocket upgrades, HTTP/2 upstream handling, HTTP/2 to HTTP/1.1 fallback, dynamic api_key command execution, health checks, reload or hot-upgrade behavior, CI security checks, or any other Security/Safe-sensitive change. Also use when the review must verify cargo clippy, cargo audit, and test coverage expectations before merge.
---

# OpenProxy Security Review

Review the change as a security review, not a style pass. Treat regressions in auth isolation, protocol parsing, upstream credential handling, or fallback behavior as release blockers until disproven.

## Workflow

1. Read the diff first.
   Start with `git status --short`, `git diff --stat`, and `git diff -- <changed-files>`.
2. Expand from the diff into the affected runtime path.
   Read the touched module plus the adjacent auth, protocol, and tests for the same path.
3. Run the baseline checks.
   Use `scripts/run_review_checks.sh <repo-root>` unless the user explicitly asked for a narrower pass.
4. Review attack-surface invariants before reviewing code style.
   Focus on credential leakage, ambiguous parsing, auth bypass, unsafe protocol fallback, shell-command execution, denial-of-service risk, and stale or inconsistent provider selection.
5. Review test coverage.
   Every security-sensitive behavior change needs Rust unit tests in the touched module and an explicit statement of which CI E2E scenarios should cover it.
6. Write findings first.
   Order by severity, include file and line references, explain exploitability or regression impact, then list open questions and residual gaps.

## Local Checks

Run these from the repository root unless the change is docs-only:

```bash
scripts/run_review_checks.sh .
```

Use the script flags when needed:

```bash
scripts/run_review_checks.sh --with-build .
scripts/run_review_checks.sh --all-tests .
```

Interpretation:

- `cargo fmt --all --check` must pass.
- `cargo clippy --all-targets --all-features -- -D warnings` must pass.
- `cargo test --lib --verbose` is the default local test floor.
- `cargo audit` must pass or the review is incomplete.
- Do not run `e2e/test_*.py` locally for this repository. Map the change to `.github/workflows/e2e.yml` coverage instead.

If a required tool is missing, say so explicitly and treat the review as blocked or incomplete. Do not silently skip `cargo audit`.

## Review Priorities

Read [`references/openproxy-surface.md`](references/openproxy-surface.md) for the project-specific module map, invariants, and test mapping.

Read [`references/review-checklist.md`](references/review-checklist.md) when you need the detailed Rust, HTTP proxy, and LLM-specific checklist.

Prioritize these areas:

- HTTP request parsing and framing changes in `src/http/` and `src/http/reader/`.
- Header filtering, auth extraction, provider selection, CONNECT, WebSocket, and H2 fallback changes in `src/worker/`.
- Provider auth, dynamic command execution, and extra-header transformation changes in `src/provider/`.
- Config parsing, health checks, listener setup, and fallback selection changes in `src/lib.rs`.
- Hot reload and hot-upgrade behavior in `src/main.rs`.
- Dependency or workflow changes in `Cargo.toml`, `Cargo.lock`, `Dockerfile`, and `.github/workflows/`.

## Blocker Heuristics

Assume the change is risky and report a finding if it does any of the following without strong justification and tests:

- Introduces new `unsafe`, `unwrap`, `expect`, `panic!`, or `todo!` on paths reachable from untrusted input.
- Logs secrets, API keys, raw auth headers, provider tokens, or command output.
- Changes header filtering so client credentials can reach upstream unintentionally.
- Re-accepts ambiguous HTTP framing such as duplicate `Content-Length`, duplicate `Transfer-Encoding`, or mixed `Content-Length` plus `chunked`.
- Changes provider selection ordering so fallback, priority, or auth matching can be bypassed.
- Makes `forward` inherit auth behavior meant only for authenticating providers.
- Changes dynamic `api_key: $(...)` handling without preserving timeout, sanitization, and failure behavior.
- Makes HTTP/2 fallback or WebSocket forwarding bypass the same auth and header filtering invariants as HTTP/1.1.
- Holds locks across network I/O or adds blocking work to hot request paths without calling out the DoS tradeoff.

## Coverage Bar

For security-sensitive changes, require both:

- Unit tests in the touched Rust module.
- Expected CI E2E coverage called out by name when the behavior spans protocols, auth, reload, or provider semantics.

Minimum expectations by change type:

- HTTP parsing or header filtering: update `src/http/mod.rs` or `src/worker/mod.rs` tests and cite the matching E2E auth/parsing suites.
- Auth or provider selection: update `src/provider/mod.rs`, `src/lib.rs`, or `src/worker/mod.rs` tests and cite the matching auth-selection E2E suites.
- CONNECT, WebSocket, H2, or fallback: update `src/worker/mod.rs` or `src/h2client/mod.rs` tests and cite the protocol E2E suites.
- Reload, hot-upgrade, or dynamic credentials: add unit coverage where practical and cite the exact reload or dynamic-auth E2E suites.

If the change spans HTTP/1.1 and HTTP/2, expect coverage for both paths or an explicit argument for why one path is impossible.

## Output Format

Use this structure:

1. Findings
2. Open questions or assumptions
3. Checks run
4. Test coverage assessment

If there are no findings, say that explicitly, then call out residual risk or missing coverage. Keep the emphasis on security and safety, not general refactoring advice.
