#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
impl_script="${repo_root}/.agents/skills/openproxy-security-review/scripts/run_review_checks.sh"

if [[ ! -f "${impl_script}" ]]; then
  echo "missing review check implementation: ${impl_script}" >&2
  exit 127
fi

exec bash "${impl_script}" "$@"
