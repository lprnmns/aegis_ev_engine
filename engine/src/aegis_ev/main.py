from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .adapters.safe_headers import fetch_and_analyze_headers
from .audit import AuditLog
from .models import AuthorizationProfile, Environment, ImpactLevel, PolicyBudget, RequestBudget, ToolIntent
from .policy import PolicyEngine


def _json_default(value):
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    return str(value)


def validate_command(args: argparse.Namespace) -> int:
    audit = AuditLog(args.audit_log)
    now = datetime.now(timezone.utc)
    auth = AuthorizationProfile(
        owner="local-user",
        allowed_domains=args.allow_domain,
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(hours=1),
        environment=Environment.DEVELOPMENT,
        allowed_impact_levels=[ImpactLevel.GREEN],
        request_budget=PolicyBudget(max_requests=1),
    )
    intent = ToolIntent(
        adapter="safe_headers",
        target=args.target,
        impact=ImpactLevel.GREEN,
        budget=RequestBudget(max_requests=1, timeout_seconds=args.timeout),
        reason="Low-impact HTTP security header check",
    )

    decision = PolicyEngine().evaluate(intent, auth)
    audit.append_policy_decision(decision, actor="system")

    if not decision.allowed:
        print(json.dumps({"decision": decision.decision.value, "reason": decision.reason}, indent=2))
        return 2

    result = fetch_and_analyze_headers(args.target, timeout_seconds=args.timeout)
    audit.append(
        actor="adapter.safe_headers",
        action="adapter.completed",
        target=args.target,
        details={"evidence_id": result.evidence.id, "finding_count": len(result.findings)},
        event_type="adapter_event",
        normalized_target=decision.normalized_target,
        impact_level=ImpactLevel.GREEN.value,
    )
    print(json.dumps({
        "decision": decision.decision.value,
        "evidence": asdict(result.evidence),
        "findings": [asdict(f) for f in result.findings],
    }, indent=2, default=_json_default))
    return 0


def audit_verify_command(args: argparse.Namespace) -> int:
    audit = AuditLog(args.audit_log)
    result = audit.verify()
    print(json.dumps({
        "audit_log": str(args.audit_log),
        "valid": result.valid,
        "event_count": result.event_count,
        "last_hash": result.last_hash,
        "errors": result.errors,
    }, indent=2))
    return 0 if result.valid else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis-ev", description="AegisEV safe validation engine")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="Run a safe policy-gated header validation")
    validate.add_argument("--target", required=True)
    validate.add_argument("--allow-domain", action="append", required=True)
    validate.add_argument("--timeout", type=int, default=10)
    validate.add_argument("--audit-log", type=Path, default=Path(".aegis/audit.jsonl"))
    validate.set_defaults(func=validate_command)

    audit_verify = sub.add_parser("audit-verify", help="Verify audit log hash chain")
    audit_verify.add_argument("--audit-log", type=Path, default=Path(".aegis/audit.jsonl"))
    audit_verify.set_defaults(func=audit_verify_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
