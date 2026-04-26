#!/usr/bin/env python3
"""Local file-based Codex/Gemini relay for Aegis EV."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path.cwd()
STATE_PATH = ROOT / ".agent" / "state" / "current-task.json"
REPORT_DIR = ROOT / ".agent" / "reports"
TMP_DIR = ROOT / ".agent" / "tmp"
CODEX_LATEST = REPORT_DIR / "codex-builder-latest.md"
GEMINI_LATEST = REPORT_DIR / "gemini-qa-latest.md"
VERDICT_RE = re.compile(r"^Verdict: (PASS|CONDITIONAL_PASS|FAIL)$", re.MULTILINE)
PROMPT_ARG_LIMIT = 100_000


class RelayError(RuntimeError):
    """Raised for safe relay stops."""


def status(message: str) -> None:
    print(f"[local-relay] {message}", flush=True)


def run_cmd(
    args: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=capture,
        check=check,
    )


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def git(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run_cmd(["git", *args], check=check)


def require_repo_root() -> None:
    if not (ROOT / "AGENTS.md").exists() or not (ROOT / ".git").exists():
        raise RelayError("Run this script from the repository root.")
    top = git(["rev-parse", "--show-toplevel"]).stdout.strip()
    if Path(top) != ROOT:
        raise RelayError(f"Run this script from the repository root: {top}")


def current_branch() -> str:
    branch = git(["symbolic-ref", "--quiet", "--short", "HEAD"], check=False).stdout.strip()
    if not branch:
        raise RelayError("Detached HEAD is not supported.")
    return branch


def enforce_branch_rules(branch: str, dry_run: bool) -> None:
    if branch in {"main", "beta"} and not dry_run:
        raise RelayError(f"Refusing to run on protected branch {branch}.")
    if not branch.startswith("feat/") and not dry_run:
        raise RelayError(f"Refusing to run on non-feature branch {branch}. Expected feat/*.")
    if dry_run and not branch.startswith("feat/"):
        status(f"dry-run branch warning: {branch} is not feat/*")


def working_tree_dirty() -> bool:
    return bool(git(["status", "--porcelain"]).stdout.strip())


def enforce_clean_tree(allow_dirty: bool, dry_run: bool) -> None:
    if not working_tree_dirty():
        return
    if allow_dirty:
        status("working tree is dirty; continuing because --allow-dirty was set")
        return
    if dry_run:
        status("working tree is dirty; continuing because --dry-run is non-mutating")
        return
    raise RelayError("Working tree is dirty. Commit/stash changes or rerun with --allow-dirty.")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return f"[missing: {path}]"


def write_text(path: Path, value: str, dry_run: bool) -> None:
    if dry_run:
        status(f"dry-run: would write {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def load_state(task_id: str, branch: str, max_loops: int) -> dict[str, Any]:
    if STATE_PATH.exists():
        state = json.loads(read_text(STATE_PATH))
    else:
        state = {}
    state.setdefault("task_id", task_id)
    state["branch"] = branch
    state.setdefault("base_branch", "beta")
    state.setdefault("status", "in_progress")
    state.setdefault("loop_count", 0)
    state["max_loops"] = max_loops
    state.setdefault("last_codex_commit", None)
    state.setdefault("last_gemini_verdict", None)
    state.setdefault("next_actor", "gemini")
    state.setdefault("blocked", False)
    return state


def save_state(state: dict[str, Any], dry_run: bool) -> None:
    write_text(STATE_PATH, json.dumps(state, indent=2) + "\n", dry_run)


def list_adr_context() -> str:
    parts: list[str] = []
    for path in sorted((ROOT / "adr").glob("*.md")):
        parts.append(f"## {path}\n{read_text(path)}")
    return "\n\n".join(parts)


def base_ref(base_branch: str) -> str | None:
    for candidate in (base_branch, f"origin/{base_branch}"):
        result = git(["rev-parse", "--verify", candidate], check=False)
        if result.returncode == 0:
            return candidate
    return None


def limited(value: str, limit: int = 80_000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n\n[truncated for prompt size]\n"


def git_diff_context(base_branch: str) -> str:
    ref = base_ref(base_branch)
    if not ref:
        return f"[base branch {base_branch!r} not found locally]"
    stat = git(["diff", "--stat", f"{ref}...HEAD"], check=False).stdout
    diff = git(["diff", f"{ref}...HEAD"], check=False).stdout
    return f"## Diff Stat Against {ref}\n{stat}\n\n## Diff Against {ref}\n{limited(diff)}"


def build_context(task_id: str, state: dict[str, Any]) -> str:
    docs = [
        "docs/00_EXECUTIVE_DECISION.md",
        "docs/01_PRD.md",
        "docs/02_SOFTWARE_ARCHITECTURE.md",
        "docs/03_SECURITY_GUARDRAILS.md",
        "docs/16_AGENT_COLLABORATION_WORKFLOW.md",
        "docs/17_LOCAL_AGENT_RELAY.md",
    ]
    parts = [
        f"# Relay Context for {task_id}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "## AGENTS.md",
        read_text(ROOT / "AGENTS.md"),
    ]
    for doc in docs:
        parts.extend([f"## {doc}", read_text(ROOT / doc)])
    parts.extend(
        [
            "## ADRs",
            list_adr_context(),
            "## Project Memory",
            read_text(ROOT / ".agent" / "state" / "project-memory.md"),
            "## Current Task State",
            json.dumps(state, indent=2),
            "## Latest Codex Builder Report",
            read_text(CODEX_LATEST),
            "## Latest Gemini QA Report",
            read_text(GEMINI_LATEST),
            "## Git Diff Context",
            git_diff_context(str(state.get("base_branch", "beta"))),
        ]
    )
    return "\n\n".join(parts)


def build_prompt(template_path: Path, task_id: str, state: dict[str, Any]) -> str:
    template = read_text(template_path)
    context = build_context(task_id, state)
    return f"{template}\n\n---\n\n{context}"


def parse_verdict(output: str) -> tuple[str | None, str | None]:
    matches = VERDICT_RE.findall(output)
    if len(matches) == 1:
        return matches[0], None
    if not matches:
        return None, "Gemini output did not contain a valid verdict line."
    return None, "Gemini output contained more than one verdict line."


def gemini_shell_prefix() -> str:
    return (
        'if ! command -v gemini >/dev/null 2>&1 && [ -s "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]; then '
        '. "${NVM_DIR:-$HOME/.nvm}/nvm.sh"; '
        'nvm use --lts >/dev/null; '
        'fi; '
    )


def call_gemini(prompt: str, model: str | None) -> str:
    args = ["gemini"]
    if model:
        args.extend(["-m", model])
    if len(prompt) <= PROMPT_ARG_LIMIT:
        args.extend(["-p", prompt])
        command = gemini_shell_prefix() + " ".join(shell_quote(arg) for arg in args)
        result = run_cmd(["bash", "-lc", command], check=False)
        return (result.stdout or "") + (result.stderr or "")

    TMP_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=TMP_DIR, prefix="gemini-prompt-", suffix=".md", delete=False
    ) as handle:
        handle.write(prompt)
        temp_path = Path(handle.name)
    try:
        short_prompt = (
            "Read the local prompt file below and respond to that prompt. "
            "Do not print secrets or inspect credential files.\n\n"
            f"Prompt file: {temp_path}"
        )
        args.extend(["-p", short_prompt])
        command = gemini_shell_prefix() + " ".join(shell_quote(arg) for arg in args)
        result = run_cmd(["bash", "-lc", command], check=False)
        return (result.stdout or "") + (result.stderr or "")
    finally:
        temp_path.unlink(missing_ok=True)


def call_codex(prompt: str, model: str | None) -> str:
    args = ["codex", "exec", "--full-auto", "--sandbox", "workspace-write"]
    if model:
        args.extend(["--model", model])
    args.append("-")
    result = run_cmd(args, input_text=prompt, check=False)
    return (result.stdout or "") + (result.stderr or "")


def run_validations() -> list[tuple[str, int, str]]:
    validations = [
        ["./scripts/run_tests.sh"],
        ["git", "diff", "--check"],
    ]
    results: list[tuple[str, int, str]] = []
    for command in validations:
        result = run_cmd(command, check=False)
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        results.append((" ".join(command), result.returncode, output))
    return results


def validation_report(results: list[tuple[str, int, str]]) -> str:
    lines = []
    for command, code, output in results:
        status_text = "passed" if code == 0 else f"failed with exit {code}"
        lines.append(f"- `{command}` - {status_text}")
        if output:
            lines.append("")
            lines.append("```text")
            lines.append(limited(output, 4_000).rstrip())
            lines.append("```")
    return "\n".join(lines)


def commit_and_push_if_changed(task_id: str, branch: str, dry_run: bool) -> str | None:
    if not working_tree_dirty():
        status("no file changes to commit")
        return None
    if dry_run:
        status("dry-run: would commit and push changed files")
        return None
    git(["add", "."])
    git(["commit", "-m", f"chore(agent): local relay update for {task_id}"])
    commit_hash = git(["rev-parse", "HEAD"]).stdout.strip()
    git(["push", "origin", f"HEAD:{branch}"])
    status(f"pushed {commit_hash} to {branch}")
    return commit_hash


def write_relay_report(
    task_id: str,
    state: dict[str, Any],
    entries: list[str],
    dry_run: bool,
) -> None:
    path = REPORT_DIR / f"local-relay-{task_id}.md"
    body = "\n\n".join(
        [
            f"# Local Relay Report: {task_id}",
            f"Updated: {datetime.now(timezone.utc).isoformat()}",
            "## State",
            "```json\n" + json.dumps(state, indent=2) + "\n```",
            "## Events",
            "\n\n".join(entries) if entries else "- No relay events recorded.",
        ]
    )
    write_text(path, body + "\n", dry_run)


def one_loop(args: argparse.Namespace, state: dict[str, Any], events: list[str], branch: str) -> bool:
    next_actor = str(state.get("next_actor", "gemini"))
    task_id = args.task_id

    if next_actor == "gemini":
        prompt = build_prompt(ROOT / ".agent" / "prompts" / "gemini" / "LOCAL_RELAY_QA.md", task_id, state)
        if args.dry_run:
            events.append("- Dry-run: generated Gemini QA prompt.")
            status("dry-run: generated Gemini QA prompt")
            if args.once:
                return False
        else:
            status("running Gemini QA")
            output = call_gemini(prompt, args.gemini_model)
            write_text(GEMINI_LATEST, output, False)
            verdict, error = parse_verdict(output)
            if error:
                state["last_gemini_verdict"] = "FAIL"
                state["status"] = "blocked"
                state["blocked"] = True
                events.append(f"- Gemini verdict invalid: {error}")
                save_state(state, False)
                return False
            state["last_gemini_verdict"] = verdict
            events.append(f"- Gemini verdict: `{verdict}`.")
            if verdict == "PASS":
                state["status"] = "passed"
                state["next_actor"] = "done"
                save_state(state, False)
                return False
            state["next_actor"] = "codex"
            save_state(state, False)
            if args.once:
                return False

    if state.get("next_actor") == "codex":
        if int(state.get("loop_count", 0)) >= int(state.get("max_loops", args.max_loops)):
            state["status"] = "blocked"
            state["blocked"] = True
            events.append("- Max loop count reached before Codex run.")
            save_state(state, args.dry_run)
            return False
        prompt = build_prompt(ROOT / ".agent" / "prompts" / "codex" / "LOCAL_RELAY_CODEX.md", task_id, state)
        if args.dry_run:
            events.append("- Dry-run: generated Codex Builder prompt.")
            status("dry-run: generated Codex Builder prompt")
            if args.once:
                return False
        else:
            status("running Codex Builder")
            output = call_codex(prompt, args.codex_model)
            write_text(CODEX_LATEST, output, False)
            validation_results = run_validations()
            events.append("## Validation Results\n\n" + validation_report(validation_results))
            if any(code != 0 for _, code, _ in validation_results):
                state["status"] = "blocked"
                state["blocked"] = True
                save_state(state, False)
                return False
            commit_hash = commit_and_push_if_changed(task_id, branch, False)
            state["last_codex_commit"] = commit_hash
            state["loop_count"] = int(state.get("loop_count", 0)) + 1
            state["next_actor"] = "gemini"
            state["status"] = "in_progress"
            save_state(state, False)
            if args.once:
                return False

    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local Codex/Gemini agent relay.")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--max-loops", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--sleep-seconds", type=int, default=10)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--codex-model")
    parser.add_argument("--gemini-model")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    events: list[str] = []
    try:
        require_repo_root()
        branch = current_branch()
        status(f"branch: {branch}")
        enforce_branch_rules(branch, args.dry_run)
        enforce_clean_tree(args.allow_dirty, args.dry_run)
        state = load_state(args.task_id, branch, args.max_loops)
        if state.get("blocked") and not args.dry_run:
            raise RelayError("Current task state is blocked. Clear the block after human review.")
        save_state(state, args.dry_run)

        keep_running = True
        while keep_running:
            if int(state.get("loop_count", 0)) > int(state.get("max_loops", args.max_loops)):
                state["status"] = "blocked"
                state["blocked"] = True
                events.append("- Max loop count exceeded.")
                save_state(state, args.dry_run)
                break
            keep_running = one_loop(args, state, events, branch)
            if args.once:
                break
            if keep_running:
                time.sleep(max(args.sleep_seconds, 0))
        write_relay_report(args.task_id, state, events, args.dry_run)
        status("relay finished")
        return 0
    except RelayError as exc:
        print(f"[local-relay] ERROR: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        output = ((exc.stdout or "") + (exc.stderr or "")).strip()
        print(f"[local-relay] ERROR: command failed: {' '.join(exc.cmd)}", file=sys.stderr)
        if output:
            print(textwrap.shorten(output, width=1000, placeholder=" ..."), file=sys.stderr)
        return exc.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
