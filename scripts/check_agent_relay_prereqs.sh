#!/usr/bin/env bash
set -euo pipefail

failures=0

note() {
  printf '%s\n' "$1"
}

require_cmd() {
  local name="$1"
  local hint="$2"
  if command -v "$name" >/dev/null 2>&1; then
    note "OK: found $name"
  else
    note "MISSING: $name"
    note "Hint: $hint"
    failures=$((failures + 1))
  fi
}

if ! command -v git >/dev/null 2>&1; then
  note "MISSING: git"
  note "Hint: install git and run this script from the repository root."
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$repo_root" ]]; then
  note "FAIL: not inside a git repository."
  exit 1
fi

if [[ "$PWD" != "$repo_root" ]]; then
  note "FAIL: run this script from the repository root: $repo_root"
  exit 1
fi
note "OK: running from repo root"

branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
if [[ -z "$branch" ]]; then
  note "FAIL: detached HEAD is not supported."
  failures=$((failures + 1))
else
  note "OK: current branch is $branch"
fi

require_cmd codex "Install and log in to the local Codex CLI using its normal account login flow. Do not add API keys to this repo."
require_cmd gemini "Install and log in to the local Gemini CLI using its normal account login flow. Do not add API keys to this repo."

if [[ -x scripts/run_tests.sh ]]; then
  if ./scripts/run_tests.sh; then
    note "OK: scripts/run_tests.sh passed"
  else
    note "FAIL: scripts/run_tests.sh failed"
    failures=$((failures + 1))
  fi
else
  note "FAIL: scripts/run_tests.sh is missing or not executable"
  failures=$((failures + 1))
fi

if [[ "$failures" -ne 0 ]]; then
  note "Prerequisite check failed with $failures issue(s)."
  exit 1
fi

note "Prerequisite check passed."
