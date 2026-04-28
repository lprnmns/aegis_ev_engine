from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Mapping

from .audit import AuditEvent, AuditLog, GENESIS_HASH, canonical_json, redact_target, redact_value
from .evidence import (
    EvidenceRecord,
    EvidenceSourceType,
    EvidenceType,
    FindingConfidence,
    FindingRecord,
    FindingStatus,
    RetestStatus,
    VerificationState,
)


CHECK_TYPES = {
    "candidate_observation_removed",
    "disclosure_reduced",
    "header_absent",
    "header_present",
    "header_value_contains",
    "human_review_required",
}
RETEST_RESULTS = {"inconclusive", "not_tested", "regressed", "resolved", "unchanged"}


@dataclass(frozen=True)
class RemediationGuidance:
    guidance_id: str
    finding_id: str
    title: str
    summary: str
    affected_target: str | None
    finding_category: str
    severity: str
    recommended_actions: tuple[str, ...]
    configuration_examples: tuple[str, ...]
    verification_steps: tuple[str, ...]
    safety_notes: tuple[str, ...]
    references: tuple[str, ...]
    confidence: str
    generated_from: str
    evidence_ids: tuple[str, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class RetestStep:
    step_id: str
    finding_id: str
    title: str
    check_type: str
    expected_condition: str
    safe_method: str = "HEAD"
    impact_level: str = "green"
    required_approval: bool = False
    status: str = "planned"
    rationale: str = ""
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "check_type", self.check_type if self.check_type in CHECK_TYPES else "human_review_required")
        object.__setattr__(self, "safe_method", "HEAD" if str(self.safe_method).upper() not in {"HEAD", "GET"} else str(self.safe_method).upper())
        object.__setattr__(self, "impact_level", self.impact_level if self.impact_level in {"green", "amber", "red"} else "green")
        object.__setattr__(self, "evidence_ids", tuple(sorted({str(item) for item in self.evidence_ids})))
        object.__setattr__(self, "metadata", redact_value(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class RetestPlan:
    retest_plan_id: str
    created_at_utc: str
    target: str | None
    normalized_target: str | None
    finding_ids: tuple[str, ...]
    retest_steps: tuple[RetestStep, ...]
    expected_observations: tuple[str, ...]
    required_policy_scope: dict[str, Any]
    safe_mode_required: bool = True
    allowed_methods: tuple[str, ...] = ("HEAD",)
    max_redirects: int = 3
    timeout_seconds: int = 5
    required_evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "retest_plan_id": self.retest_plan_id,
                "created_at_utc": self.created_at_utc,
                "target": self.target,
                "normalized_target": self.normalized_target,
                "finding_ids": list(self.finding_ids),
                "retest_steps": [step.to_dict() for step in self.retest_steps],
                "expected_observations": list(self.expected_observations),
                "required_policy_scope": self.required_policy_scope,
                "safe_mode_required": self.safe_mode_required,
                "allowed_methods": list(self.allowed_methods),
                "max_redirects": self.max_redirects,
                "timeout_seconds": self.timeout_seconds,
                "required_evidence_ids": list(self.required_evidence_ids),
                "warnings": list(self.warnings),
                "metadata": self.metadata,
            }
        )


@dataclass(frozen=True)
class FindingRetestResult:
    finding_id: str
    previous_status: str
    new_retest_status: str
    result: str
    rationale: str
    before_observation: dict[str, Any]
    after_observation: dict[str, Any]
    evidence_ids: tuple[str, ...]
    requires_human_review: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "result", self.result if self.result in RETEST_RESULTS else "inconclusive")
        object.__setattr__(self, "before_observation", redact_value(self.before_observation))
        object.__setattr__(self, "after_observation", redact_value(self.after_observation))
        object.__setattr__(self, "evidence_ids", tuple(sorted({str(item) for item in self.evidence_ids})))

    def to_dict(self) -> dict[str, Any]:
        return redact_value(asdict(self))


@dataclass(frozen=True)
class RetestResult:
    retest_result_id: str
    created_at_utc: str
    retest_plan_id: str
    target: str | None
    normalized_target: str | None
    finding_results: tuple[FindingRetestResult, ...]
    resolved_count: int
    unchanged_count: int
    regressed_count: int
    inconclusive_count: int
    evidence_ids: tuple[str, ...]
    audit_verification_status: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "retest_result_id": self.retest_result_id,
                "created_at_utc": self.created_at_utc,
                "retest_plan_id": self.retest_plan_id,
                "target": self.target,
                "normalized_target": self.normalized_target,
                "finding_results": [item.to_dict() for item in self.finding_results],
                "resolved_count": self.resolved_count,
                "unchanged_count": self.unchanged_count,
                "regressed_count": self.regressed_count,
                "inconclusive_count": self.inconclusive_count,
                "evidence_ids": list(self.evidence_ids),
                "audit_verification_status": self.audit_verification_status,
                "warnings": list(self.warnings),
                "errors": list(self.errors),
                "metadata": self.metadata,
            }
        )


def generate_remediation_guidance(payload: Mapping[str, Any]) -> RemediationGuidance:
    finding = _finding(payload)
    fingerprint = _object(payload.get("technology_fingerprint") or payload.get("fingerprint"))
    title = str(finding.get("title") or "")
    category = _template_key(finding)
    template = _template(category)
    examples = list(template["examples"])
    frameworks = {str(item) for item in fingerprint.get("detected_frameworks", [])}
    platforms = {str(item) for item in fingerprint.get("detected_platforms", [])}
    if "Next.js" in frameworks:
        examples.append("Next.js option: define defensive response headers in next.config.js headers() when that matches the owner-approved deployment path.")
    if "Vercel" in platforms:
        examples.append("Vercel option: define defensive response headers in vercel.json or project header settings when that matches the verified deployment model.")
    guidance = RemediationGuidance(
        guidance_id=_stable_id("guidance", finding.get("finding_id"), title, category, examples),
        finding_id=str(finding.get("finding_id") or _stable_id("finding", title)),
        title=f"Remediation guidance: {title or template['title']}",
        summary=template["summary"],
        affected_target=redact_target(finding.get("normalized_target") or finding.get("target")),
        finding_category=str(finding.get("category") or category),
        severity=str(finding.get("severity") or "low"),
        recommended_actions=tuple(template["actions"]),
        configuration_examples=tuple(examples),
        verification_steps=tuple(template["verification"]),
        safety_notes=(
            "Apply changes through the owner's normal deployment workflow; Aegis EV does not modify the target.",
            "Verify with safe metadata/header collection only unless a future task explicitly authorizes more.",
            "Guidance is defensive and deterministic; it is not an exploit validation recipe.",
        ),
        references=tuple(template["references"]),
        confidence=str(finding.get("confidence") or "medium"),
        generated_from="finding",
        evidence_ids=tuple(finding.get("evidence_ids", [])),
        metadata={"template_key": category, "framework_evidence_used": sorted(frameworks), "platform_evidence_used": sorted(platforms)},
    )
    return guidance


def create_retest_plan(payload: Mapping[str, Any]) -> RetestPlan:
    findings = [_object(item) for item in _list(payload.get("findings"))]
    if not findings:
        raise ValueError("findings are required")
    created = str(payload.get("created_at_utc") or datetime.now(timezone.utc).isoformat())
    target = str(payload.get("target") or findings[0].get("target") or "")
    normalized_target = redact_target(payload.get("normalized_target") or findings[0].get("normalized_target") or target)
    steps = tuple(_step_for_finding(finding) for finding in findings)
    evidence_ids = tuple(sorted({str(eid) for finding in findings for eid in _list(finding.get("evidence_ids"))}))
    plan = RetestPlan(
        retest_plan_id=_stable_id("retest_plan", normalized_target, [step.to_dict() for step in steps]),
        created_at_utc=created,
        target=redact_target(target),
        normalized_target=normalized_target,
        finding_ids=tuple(sorted(str(finding.get("finding_id") or _stable_id("finding", finding.get("title"))) for finding in findings)),
        retest_steps=steps,
        expected_observations=tuple(step.expected_condition for step in steps),
        required_policy_scope={"target": redact_target(target), "impact_level": "green", "safe_mode": True},
        safe_mode_required=True,
        allowed_methods=("HEAD",),
        max_redirects=int(payload.get("max_redirects", 3)),
        timeout_seconds=int(payload.get("timeout_seconds", 5)),
        required_evidence_ids=evidence_ids,
        metadata={"network_execution": False, "external_tool_execution": False, "body_storage": False},
    )
    return plan


def compare_retest_results(payload: Mapping[str, Any]) -> RetestResult:
    plan_payload = _object(payload.get("retest_plan") or payload.get("plan"))
    if plan_payload:
        plan = RetestPlan(
            retest_plan_id=str(plan_payload["retest_plan_id"]),
            created_at_utc=str(plan_payload["created_at_utc"]),
            target=plan_payload.get("target"),
            normalized_target=plan_payload.get("normalized_target"),
            finding_ids=tuple(plan_payload.get("finding_ids", [])),
            retest_steps=tuple(RetestStep(**item) for item in plan_payload.get("retest_steps", [])),
            expected_observations=tuple(plan_payload.get("expected_observations", [])),
            required_policy_scope=dict(plan_payload.get("required_policy_scope", {})),
            safe_mode_required=bool(plan_payload.get("safe_mode_required", True)),
            allowed_methods=tuple(plan_payload.get("allowed_methods", ["HEAD"])),
            max_redirects=int(plan_payload.get("max_redirects", 3)),
            timeout_seconds=int(plan_payload.get("timeout_seconds", 5)),
            required_evidence_ids=tuple(plan_payload.get("required_evidence_ids", [])),
            warnings=tuple(plan_payload.get("warnings", [])),
            metadata=dict(plan_payload.get("metadata", {})),
        )
    else:
        plan = create_retest_plan(payload)
    findings = {str(_object(item).get("finding_id")): _object(item) for item in _list(payload.get("findings"))}
    before = _normalize_headers(_dict_or_empty(payload.get("before_headers") or payload.get("before_observation", {}).get("headers")))
    after = _normalize_headers(_dict_or_empty(payload.get("after_headers") or payload.get("after_observation", {}).get("headers")))
    created = str(payload.get("created_at_utc") or datetime.now(timezone.utc).isoformat())
    evidence_ids = tuple(sorted(set(plan.required_evidence_ids + tuple(payload.get("evidence_ids", [])))))
    results = []
    for step in plan.retest_steps:
        finding = findings.get(step.finding_id, {})
        results.append(_compare_step(step, finding, before, after, evidence_ids))
    counts = {name: sum(1 for item in results if item.result == name) for name in RETEST_RESULTS}
    return RetestResult(
        retest_result_id=_stable_id("retest_result", plan.retest_plan_id, [item.to_dict() for item in results]),
        created_at_utc=created,
        retest_plan_id=plan.retest_plan_id,
        target=plan.target,
        normalized_target=plan.normalized_target,
        finding_results=tuple(results),
        resolved_count=counts["resolved"],
        unchanged_count=counts["unchanged"],
        regressed_count=counts["regressed"],
        inconclusive_count=counts["inconclusive"] + counts["not_tested"],
        evidence_ids=evidence_ids,
        metadata={"confirmed_findings_created": False, "findings_deleted": False, "network_execution": False},
    )


def update_finding_from_retest(finding: FindingRecord, result: FindingRetestResult) -> FindingRecord:
    retest_status = {
        "resolved": RetestStatus.APPEARS_RESOLVED,
        "unchanged": RetestStatus.STILL_PRESENT,
        "regressed": RetestStatus.REGRESSED,
        "inconclusive": RetestStatus.INCONCLUSIVE,
        "not_tested": RetestStatus.NOT_RETESTED,
    }.get(result.result, RetestStatus.INCONCLUSIVE)
    verification = VerificationState.HUMAN_REVIEW_REQUIRED if result.requires_human_review else finding.verification_state
    return replace(finding, retest_status=retest_status, verification_state=verification, updated_at_utc=datetime.now(timezone.utc).isoformat())


def evidence_from_remediation_guidance(guidance: RemediationGuidance) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.MANUAL_NOTE,
        source_type=EvidenceSourceType.REMEDIATION_RETEST,
        source_id=guidance.guidance_id,
        target=guidance.affected_target,
        normalized_target=guidance.affected_target,
        title="Remediation guidance",
        summary=f"Generated defensive remediation guidance for finding {guidance.finding_id}.",
        structured_data=guidance.to_dict(),
        tags=("remediation", "defensive", "no-execution"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def evidence_from_retest_plan(plan: RetestPlan) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_PLAN,
        source_type=EvidenceSourceType.REMEDIATION_RETEST,
        source_id=plan.retest_plan_id,
        target=plan.target,
        normalized_target=plan.normalized_target,
        title="Safe retest plan",
        summary=f"Retest plan contains {len(plan.retest_steps)} safe metadata/header comparison step(s).",
        structured_data=plan.to_dict(),
        tags=("retest", "planning-only", "safe-mode"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def evidence_from_retest_result(result: RetestResult) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_type=EvidenceType.ADAPTER_OUTPUT,
        source_type=EvidenceSourceType.REMEDIATION_RETEST,
        source_id=result.retest_result_id,
        target=result.target,
        normalized_target=result.normalized_target,
        title="Safe retest result",
        summary=f"Retest comparison: {result.resolved_count} appears resolved, {result.unchanged_count} still present, {result.regressed_count} regressed, {result.inconclusive_count} inconclusive.",
        structured_data=result.to_dict(),
        tags=("retest", "comparison", "safe-mode"),
        confidence=FindingConfidence.MEDIUM,
        redaction_applied=True,
    )


def remediation_retest_report_section(
    *,
    guidance: list[RemediationGuidance] | tuple[RemediationGuidance, ...] = (),
    plan: RetestPlan | None = None,
    result: RetestResult | None = None,
) -> dict[str, Any]:
    return {
        "title": "Remediation and Retest Summary",
        "remediation_guidance": [item.to_dict() for item in guidance],
        "retest_plan": plan.to_dict() if plan else None,
        "retest_results": result.to_dict() if result else None,
        "before_after_summary": [item.to_dict() for item in result.finding_results] if result else [],
        "remaining_work": _remaining_work(result),
        "limitations": [
            "Retest comparisons use supplied safe metadata/header observations.",
            "appears_resolved does not delete findings or prove exploitability was impossible.",
            "inconclusive means human review or additional authorized evidence is required.",
        ],
    }


def build_remediation_audit_event(
    event_type: str,
    *,
    target: str | None = None,
    metadata: dict[str, Any] | None = None,
    audit_log: AuditLog | None = None,
    previous_hash: str = GENESIS_HASH,
    timestamp_utc: str | None = None,
) -> AuditEvent:
    details = redact_value(metadata or {}) | {"workflow": "remediation_retest", "body_stored": False}
    if audit_log is not None:
        return audit_log.append(
            actor="remediation_retest",
            action=event_type,
            target=target,
            details=details,
            event_type=event_type,
            impact_level="green",
            allowed=True,
            required_approval=False,
        )
    return AuditLog.build_event(
        AuditLog,
        actor="remediation_retest",
        action=event_type,
        target=target,
        metadata=details,
        previous_hash=previous_hash,
        event_type=event_type,
        impact_level="green",
        allowed=True,
        required_approval=False,
        event_id=_stable_id("audit", event_type, target, details),
        timestamp_utc=timestamp_utc,
    )


def _step_for_finding(finding: dict[str, Any]) -> RetestStep:
    finding_id = str(finding.get("finding_id") or _stable_id("finding", finding.get("title")))
    key = _template_key(finding)
    check_type, condition = _condition_for_key(key)
    return RetestStep(
        step_id=_stable_id("retest_step", finding_id, key, condition),
        finding_id=finding_id,
        title=f"Retest {finding.get('title') or key}",
        check_type=check_type,
        expected_condition=condition,
        safe_method="HEAD",
        impact_level="green",
        required_approval=False,
        rationale="Compare before/after safe response metadata and header analysis only.",
        evidence_ids=tuple(finding.get("evidence_ids", [])),
        metadata={"template_key": key, "external_tool_execution": False},
    )


def _compare_step(step: RetestStep, finding: dict[str, Any], before: dict[str, str], after: dict[str, str], evidence_ids: tuple[str, ...]) -> FindingRetestResult:
    key = str(step.metadata.get("template_key") or _template_key(finding))
    before_obs = _observation_for_key(key, before)
    after_obs = _observation_for_key(key, after)
    result = "inconclusive"
    rationale = "Retest requires human review because the comparison is ambiguous."
    review = False
    if key == "missing_csp":
        result = "resolved" if bool(after.get("content-security-policy")) else "unchanged"
        rationale = "Content-Security-Policy is present after retest." if result == "resolved" else "Content-Security-Policy is still absent."
    elif key == "missing_clickjacking_protection":
        result = "resolved" if bool(after.get("x-frame-options") or "frame-ancestors" in after.get("content-security-policy", "").lower()) else "unchanged"
        rationale = "A clickjacking control is present after retest." if result == "resolved" else "Clickjacking controls are still absent."
    elif key == "missing_nosniff":
        result = "resolved" if after.get("x-content-type-options", "").lower() == "nosniff" else "unchanged"
        rationale = "X-Content-Type-Options equals nosniff after retest." if result == "resolved" else "X-Content-Type-Options: nosniff is still absent."
    elif key == "missing_referrer_policy":
        result = "resolved" if bool(after.get("referrer-policy")) else "unchanged"
        rationale = "Referrer-Policy is present after retest." if result == "resolved" else "Referrer-Policy is still absent."
    elif key == "missing_permissions_policy":
        result = "resolved" if bool(after.get("permissions-policy")) else "unchanged"
        rationale = "Permissions-Policy is present after retest." if result == "resolved" else "Permissions-Policy is still absent."
    elif key == "missing_hsts":
        result = "resolved" if bool(after.get("strict-transport-security")) else "unchanged"
        rationale = "Strict-Transport-Security is present after retest." if result == "resolved" else "Strict-Transport-Security is still absent."
    elif key in {"technology_disclosure_server", "technology_disclosure_powered_by"}:
        header = "server" if key == "technology_disclosure_server" else "x-powered-by"
        old = before.get(header, "")
        new = after.get(header, "")
        if old and not new:
            result = "resolved"
            rationale = f"{header} disclosure header is absent after retest."
        elif old and new and len(new) < len(old):
            result = "inconclusive"
            rationale = f"{header} disclosure appears reduced but requires human review."
            review = True
        elif new:
            result = "unchanged"
            rationale = f"{header} disclosure is still present."
        else:
            result = "inconclusive"
            review = True
    new_status = {
        "resolved": RetestStatus.APPEARS_RESOLVED.value,
        "unchanged": RetestStatus.STILL_PRESENT.value,
        "regressed": RetestStatus.REGRESSED.value,
        "inconclusive": RetestStatus.INCONCLUSIVE.value,
        "not_tested": RetestStatus.NOT_RETESTED.value,
    }[result]
    return FindingRetestResult(
        finding_id=step.finding_id,
        previous_status=str(finding.get("status", finding.get("retest_status", RetestStatus.NOT_RETESTED.value))),
        new_retest_status=new_status,
        result=result,
        rationale=rationale,
        before_observation=before_obs,
        after_observation=after_obs,
        evidence_ids=evidence_ids,
        requires_human_review=review or result == "inconclusive",
    )


def _condition_for_key(key: str) -> tuple[str, str]:
    return {
        "missing_csp": ("header_present", "Content-Security-Policy header present and non-empty"),
        "missing_clickjacking_protection": ("header_present", "X-Frame-Options or CSP frame-ancestors present"),
        "missing_nosniff": ("header_value_contains", "X-Content-Type-Options equals nosniff"),
        "missing_referrer_policy": ("header_present", "Referrer-Policy header present and non-empty"),
        "missing_permissions_policy": ("header_present", "Permissions-Policy header present and non-empty"),
        "missing_hsts": ("header_present", "Strict-Transport-Security header present and non-empty"),
        "technology_disclosure_server": ("disclosure_reduced", "Server header absent or reduced"),
        "technology_disclosure_powered_by": ("disclosure_reduced", "X-Powered-By header absent or reduced"),
    }.get(key, ("human_review_required", "Human review required"))


def _template_key(finding: dict[str, Any]) -> str:
    title = str(finding.get("title", "")).lower()
    tags = {str(tag).lower() for tag in _list(finding.get("tags"))}
    if "content-security-policy" in title or "csp" in tags:
        return "missing_csp"
    if "clickjacking" in title or "x-frame-options" in title:
        return "missing_clickjacking_protection"
    if "nosniff" in title or "x-content-type-options" in title:
        return "missing_nosniff"
    if "referrer-policy" in title:
        return "missing_referrer_policy"
    if "permissions-policy" in title:
        return "missing_permissions_policy"
    if "strict-transport-security" in title or "hsts" in tags:
        return "missing_hsts"
    if "x-powered-by" in title:
        return "technology_disclosure_powered_by"
    if "server header" in title or ("disclosure" in tags and "server" in title):
        return "technology_disclosure_server"
    return "generic"


def _template(key: str) -> dict[str, Any]:
    templates = {
        "missing_csp": {
            "title": "Missing Content-Security-Policy",
            "summary": "Define a defensive Content-Security-Policy that matches the application asset model.",
            "actions": ("Inventory required script/style/connect sources.", "Start with a restrictive default-src policy and add only required sources.", "Roll out carefully in report-only mode first when appropriate."),
            "examples": ("Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",),
            "verification": ("Collect safe HTTP metadata.", "Confirm Content-Security-Policy is present and non-empty.", "Review policy content with the owner before treating as complete."),
            "references": ("OWASP Secure Headers Project", "CWE-693"),
        },
        "missing_clickjacking_protection": {
            "title": "Missing clickjacking controls",
            "summary": "Add an anti-framing control appropriate for the application.",
            "actions": ("Set X-Frame-Options where compatible.", "Prefer CSP frame-ancestors for modern applications.", "Confirm legitimate embedding requirements with the owner."),
            "examples": ("X-Frame-Options: DENY", "Content-Security-Policy: frame-ancestors 'none'"),
            "verification": ("Collect safe HTTP metadata.", "Confirm X-Frame-Options or CSP frame-ancestors is present."),
            "references": ("CWE-1021", "OWASP Secure Headers Project"),
        },
        "missing_nosniff": {
            "title": "Missing nosniff",
            "summary": "Set X-Content-Type-Options to nosniff.",
            "actions": ("Add the X-Content-Type-Options header.", "Keep accurate Content-Type values for served assets."),
            "examples": ("X-Content-Type-Options: nosniff",),
            "verification": ("Collect safe HTTP metadata.", "Confirm X-Content-Type-Options equals nosniff."),
            "references": ("OWASP Secure Headers Project", "CWE-16"),
        },
        "missing_referrer_policy": {
            "title": "Missing Referrer-Policy",
            "summary": "Set a privacy-preserving Referrer-Policy.",
            "actions": ("Choose a policy that balances privacy and analytics needs.", "Avoid unnecessarily exposing full URLs cross-origin."),
            "examples": ("Referrer-Policy: strict-origin-when-cross-origin", "Referrer-Policy: no-referrer"),
            "verification": ("Collect safe HTTP metadata.", "Confirm Referrer-Policy is present."),
            "references": ("OWASP Secure Headers Project", "CWE-200"),
        },
        "missing_permissions_policy": {
            "title": "Missing Permissions-Policy",
            "summary": "Define least-privilege browser feature permissions.",
            "actions": ("Disable unused browser features.", "Allow only features required by the application."),
            "examples": ("Permissions-Policy: camera=(), microphone=(), geolocation=()",),
            "verification": ("Collect safe HTTP metadata.", "Confirm Permissions-Policy is present."),
            "references": ("OWASP Secure Headers Project", "CWE-16"),
        },
        "missing_hsts": {
            "title": "Missing HSTS",
            "summary": "Add Strict-Transport-Security after confirming HTTPS readiness.",
            "actions": ("Validate all subdomains and redirects are HTTPS-ready before broad rollout.", "Start with an appropriate max-age and increase after monitoring."),
            "examples": ("Strict-Transport-Security: max-age=31536000; includeSubDomains",),
            "verification": ("Collect safe HTTP metadata.", "Confirm Strict-Transport-Security is present."),
            "references": ("OWASP Secure Headers Project", "CWE-319"),
        },
        "technology_disclosure_server": {
            "title": "Technology disclosure via Server",
            "summary": "Reduce unnecessary platform/version disclosure in Server headers where operationally feasible.",
            "actions": ("Review reverse proxy and hosting header controls.", "Remove version details where the platform supports it."),
            "examples": ("Server: <generic platform value>",),
            "verification": ("Collect safe HTTP metadata.", "Confirm disclosure is absent or reduced; human review may be required."),
            "references": ("CWE-200",),
        },
        "technology_disclosure_powered_by": {
            "title": "Technology disclosure via X-Powered-By",
            "summary": "Remove X-Powered-By where it is not operationally required.",
            "actions": ("Disable framework powered-by headers where supported.", "Confirm the change does not affect application behavior."),
            "examples": ("X-Powered-By header absent",),
            "verification": ("Collect safe HTTP metadata.", "Confirm X-Powered-By is absent or reduced."),
            "references": ("CWE-200",),
        },
    }
    return templates.get(
        key,
        {
            "title": "Generic remediation guidance",
            "summary": "Review the evidence-backed observation and apply the least-risk defensive correction.",
            "actions": ("Review evidence with the owner.", "Apply defensive configuration changes through normal deployment.", "Retest with safe metadata/header checks."),
            "examples": (),
            "verification": ("Collect safe metadata.", "Compare before/after observations.", "Escalate inconclusive results to human review."),
            "references": (),
        },
    )


def _observation_for_key(key: str, headers: dict[str, str]) -> dict[str, Any]:
    names = {
        "missing_csp": ("content-security-policy",),
        "missing_clickjacking_protection": ("x-frame-options", "content-security-policy"),
        "missing_nosniff": ("x-content-type-options",),
        "missing_referrer_policy": ("referrer-policy",),
        "missing_permissions_policy": ("permissions-policy",),
        "missing_hsts": ("strict-transport-security",),
        "technology_disclosure_server": ("server",),
        "technology_disclosure_powered_by": ("x-powered-by",),
    }.get(key, ())
    return {"headers": {name: headers.get(name) for name in names if headers.get(name)}}


def _remaining_work(result: RetestResult | None) -> list[str]:
    if result is None:
        return ["Create and execute a safe retest comparison when owner-approved after remediation."]
    work = []
    if result.unchanged_count:
        work.append("Some observations are still present and may need additional remediation.")
    if result.inconclusive_count:
        work.append("Some observations require human review or additional authorized evidence.")
    if result.regressed_count:
        work.append("Some observations regressed and should be reviewed before further testing.")
    return work or ["All compared observations appear resolved; retain evidence and schedule normal review."]


def _finding(payload: Mapping[str, Any]) -> dict[str, Any]:
    finding = _object(payload.get("finding") or payload)
    if not finding.get("title") and not finding.get("finding_id"):
        raise ValueError("finding is required")
    return finding


def _normalize_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        if value is None:
            continue
        normalized[str(key).lower()] = str(redact_value(value)).strip()
    return normalized


def _object(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_" + hashlib.sha256(canonical_json(redact_value(parts)).encode("utf-8")).hexdigest()[:24]
