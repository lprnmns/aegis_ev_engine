from __future__ import annotations

import argparse
import sys

from .contracts import failure, load_json_input, run_contract_command


MACHINE_COMMANDS = (
    "validate-policy",
    "plan-adapter",
    "analyze-web-headers",
    "import-openapi",
    "import-postman",
    "import-har",
    "render-report",
    "verify-audit",
    "create-approval",
    "list-approvals",
    "approve-action",
    "reject-action",
    "consume-approval",
    "approval-status",
    "create-project",
    "get-project",
    "list-projects",
    "add-target",
    "list-targets",
    "create-session",
    "get-session",
    "list-sessions",
    "update-session-status",
    "validate-project-target",
    "link-project-reference",
    "run-demo-flow",
    "demo-flow",
    "fetch-http-metadata",
    "fetch-and-analyze-headers",
    "fingerprint-technology",
    "build-attack-surface-graph",
    "map-vulnerability-intelligence",
    "plan-safe-recon",
    "list-tool-capabilities",
    "check-tool-availability",
    "plan-tool-action",
    "run-portfolio-demo",
    "run-portfolio-operator-pipeline",
    "generate-remediation-guidance",
    "create-retest-plan",
    "compare-retest-results",
    "build-ai-planner-packet",
    "validate-ai-planner-output",
    "build-ai-verifier-packet",
    "validate-ai-verifier-output",
    "build-ai-reporter-packet",
    "validate-ai-reporter-output",
    "list-model-providers",
    "build-model-request-envelope",
    "route-model-request",
    "execute-mock-model-request",
    "validate-model-response-envelope",
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
