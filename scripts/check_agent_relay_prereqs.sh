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

load_nvm_if_present() {
  if command -v nvm >/dev/null 2>&1; then
    return 0
  fi
  if [[ -s "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]]; then
    # shellcheck source=/dev/null
    . "${NVM_DIR:-$HOME/.nvm}/nvm.sh"
    return 0
  fi
  return 1
}

major_version() {
  local value="$1"
  value="${value#v}"
  printf '%s\n' "${value%%.*}"
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

if ! command -v gemini >/dev/null 2>&1; then
  load_nvm_if_present || true
fi

if command -v node >/dev/null 2>&1; then
  node_version="$(node -v)"
  node_major="$(major_version "$node_version")"
  if [[ "$node_major" -ge 20 ]]; then
    note "OK: node $node_version"
  else
    note "FAIL: node $node_version is too old for Gemini CLI; Node 20+ is required."
    note "Hint: use an existing nvm installation to install/use an LTS Node 20+ release. Do not add API keys to this repo."
    failures=$((failures + 1))
  fi
else
  note "MISSING: node"
  note "Hint: install Node 20+ using your normal local toolchain. Do not add API keys to this repo."
  failures=$((failures + 1))
fi

if command -v npm >/dev/null 2>&1; then
  note "OK: npm $(npm -v)"
else
  note "MISSING: npm"
  note "Hint: install npm with Node 20+ using your normal local toolchain. Do not add API keys to this repo."
  failures=$((failures + 1))
fi

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
