from __future__ import annotations

import argparse
import sys

from .contracts import failure, load_json_input, run_contract_command


MACHINE_COMMANDS = (
    "validate-policy",
    "plan-adapter",
    "analyze-web-headers",
    "render-report",
    "verify-audit",
    "create-approval",
    "list-approvals",
    "approve-action",
    "reject-action",
    "consume-approval",
    "approval-status",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis-ev", description="Aegis EV deterministic engine contract CLI")
    parser.add_argument("--debug", action="store_true", help="Include debug details in structured errors")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in MACHINE_COMMANDS:
        item = sub.add_parser(command, help=f"Run {command} contract command")
        item.add_argument("--input-file", help="Path to JSON input. Reads stdin when omitted.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    stdin_text = None if args.input_file else sys.stdin.read()
    payload, input_error = load_json_input(input_file=args.input_file, stdin_text=stdin_text)
    if input_error is not None:
        response = input_error
    else:
        try:
            response = run_contract_command(args.command, payload or {})
        except Exception as exc:  # pragma: no cover - defensive boundary for CLI users.
            details = {"type": type(exc).__name__} if args.debug else None
            response = failure(args.command, "internal_error", "Command failed", details=details)
    sys.stdout.write(response.to_json() + "\n")
    return 0 if response.ok else 1


if __name__ == "__main__":
    sys.exit(main())
