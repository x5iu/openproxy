#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_review_checks.sh [--with-build] [--all-tests] [repo-root]

Run the baseline local validation commands for OpenProxy security reviews.

Options:
  --with-build  Also run cargo build --release.
  --all-tests   Run cargo test --verbose instead of cargo test --lib --verbose.
  -h, --help    Show this help text.
EOF
}

repo_root="."
with_build=0
all_tests=0

while (($# > 0)); do
  case "$1" in
    --with-build)
      with_build=1
      shift
      ;;
    --all-tests)
      all_tests=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      repo_root="$1"
      shift
      if (($# > 0)); then
        echo "unexpected argument: $1" >&2
        usage >&2
        exit 2
      fi
      ;;
  esac
done

cd "$repo_root"

echo "[1/4] cargo fmt --all --check"
cargo fmt --all --check

echo "[2/4] cargo clippy --all-targets --all-features -- -D warnings"
cargo clippy --all-targets --all-features -- -D warnings

if ((all_tests)); then
  echo "[3/4] cargo test --verbose"
  cargo test --verbose
else
  echo "[3/4] cargo test --lib --verbose"
  cargo test --lib --verbose
fi

echo "[4/4] cargo audit"
if ! cargo audit --version >/dev/null 2>&1; then
  echo "cargo audit is required for this review but is not installed." >&2
  exit 127
fi
cargo audit

if ((with_build)); then
  echo "[5/5] cargo build --release"
  cargo build --release
fi
