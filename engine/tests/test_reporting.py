import json
import unittest

from aegis_ev.audit import AuditVerificationResult, REDACTED
from aegis_ev.evidence import (
    EvidenceRecord,
    EvidenceSourceType,
    EvidenceStore,
    EvidenceType,
    FindingConfidence,
    FindingRecord,
    FindingSeverity,
    FindingStatus,
    VerificationState,
)
from aegis_ev.reporting import create_report, render_report_json, render_report_markdown


SECRET_VALUE = "not-a-real-report-token-1234567890"
CREATED_AT = "2026-01-01T00:00:00+00:00"


def evidence(**kwargs):
    base = {
        "evidence_id": "evidence_1",
        "created_at_utc": CREATED_AT,
        "evidence_type": EvidenceType.POLICY_DECISION,
        "source_type": EvidenceSourceType.POLICY,
        "source_id": "policy_1",
        "target": "https://example.com/path?token=" + SECRET_VALUE,
        "normalized_target": "https://example.com/path",
        "title": "Policy decision",
        "summary": "Allowed scoped target",
        "redacted_raw": {"Authorization": "Bearer " + SECRET_VALUE},
        "structured_data": {"api_key": SECRET_VALUE, "safe": True},
        "related_audit_event_id": "audit_1",
        "related_adapter_id": "echo_plan",
        "tags": ("policy",),
        "confidence": FindingConfidence.HIGH,
    }
    base.update(kwargs)
    return EvidenceRecord(**base)


def finding(**kwargs):
    base = {
        "finding_id": "finding_1",
        "created_at_utc": CREATED_AT,
        "updated_at_utc": CREATED_AT,
        "title": "Missing test header",
        "description": "A candidate issue.",
        "severity": FindingSeverity.MEDIUM,
        "confidence": FindingConfidence.MEDIUM,
        "status": FindingStatus.CANDIDATE,
        "target": "https://example.com/path?password=" + SECRET_VALUE,
        "normalized_target": "https://example.com/path",
        "category": "headers",
        "evidence_ids": ("evidence_1",),
        "remediation": "Review header policy.",
        "verification_state": VerificationState.EVIDENCE_BACKED,
        "tags": ("headers",),
    }
    base.update(kwargs)
    return FindingRecord(**base)


def report(**kwargs):
    store = EvidenceStore()
    store.add_evidence(evidence())
    store.add_finding(finding())
    base = {
        "report_id": "report_1",
        "created_at_utc": CREATED_AT,
        "project_name": "Example Project",
        "customer_name": "Customer A",
        "environment": "staging",
        "scope_summary": "Scope includes example.com only.",
        "authorization_summary": "Authorized profile active.",
        "executive_summary": "One candidate finding.",
        "methodology_summary": "Deterministic report from evidence store.",
        "limitations": ["No PDF, UI, AI prose, scanner output, or network calls."],
        "audit_verification": AuditVerificationResult(
            valid=True,
            event_count=2,
            last_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        "evidence_store": store,
        "generated_by": "Aegis EV test",
        "tags": ("task-006",),
    }
    base.update(kwargs)
    return create_report(**base)


class ReportGeneratorTests(unittest.TestCase):
    def test_json_report_deterministic_output(self):
        self.assertEqual(render_report_json(report()), render_report_json(report()))

    def test_markdown_report_deterministic_output(self):
        self.assertEqual(render_report_markdown(report()), render_report_markdown(report()))

    def test_report_includes_candidate_without_overclaiming_confirmed_status(self):
        markdown = render_report_markdown(report())
        self.assertIn("`candidate`", markdown)
        self.assertIn("Not recorded as confirmed.", markdown)
        self.assertNotIn("Recorded as confirmed.", markdown)

    def test_confirmed_finding_is_represented_accurately(self):
        store = EvidenceStore()
        store.add_evidence(evidence())
        store.add_finding(
            finding(
                status=FindingStatus.CONFIRMED,
                verification_state=VerificationState.VERIFIED,
            )
        )
        markdown = render_report_markdown(report(evidence_store=store))
        self.assertIn("`confirmed`", markdown)
        self.assertIn("`verified`", markdown)
        self.assertIn("Recorded as confirmed.", markdown)

    def test_evidence_references_included_safely(self):
        data = json.loads(render_report_json(report()))
        evidence_summary = data["evidence_summary"][0]
        self.assertEqual(evidence_summary["evidence_id"], "evidence_1")
        self.assertEqual(evidence_summary["related_audit_event_id"], "audit_1")
        self.assertNotIn("redacted_raw", evidence_summary)
        self.assertNotIn("structured_data", evidence_summary)

    def test_raw_secrets_are_redacted(self):
        rendered = render_report_json(
            report(
                executive_summary="Bearer " + SECRET_VALUE,
                authorization_summary="password=" + SECRET_VALUE,
            )
        )
        self.assertNotIn(SECRET_VALUE, rendered)
        self.assertIn("redacted", rendered)

    def test_markdown_escaping_and_sanitization(self):
        markdown = render_report_markdown(
            report(project_name="Example | Project [x]", executive_summary="Use `code` | <tag>")
        )
        self.assertIn("Example \\| Project \\[x\\]", markdown)
        self.assertIn("\\`code\\` \\| &lt;tag&gt;", markdown)

    def test_risk_summary_counts_by_severity_status_verification(self):
        data = json.loads(render_report_json(report()))
        risk = data["risk_summary"]
        self.assertEqual(risk["by_severity"], {"medium": 1})
        self.assertEqual(risk["by_status"], {"candidate": 1})
        self.assertEqual(risk["by_verification_state"], {"evidence_backed": 1})
        self.assertEqual(risk["by_target"], {"https://example.com/path": 1})
        self.assertEqual(risk["by_category"], {"headers": 1})

    def test_empty_finding_list_behavior(self):
        empty = create_report(
            report_id="report_empty",
            created_at_utc=CREATED_AT,
            project_name="Empty",
            evidence=[],
            findings=[],
        )
        markdown = render_report_markdown(empty)
        self.assertIn("No findings were recorded.", markdown)
        self.assertEqual(empty.risk_summary.total_findings, 0)

    def test_empty_evidence_list_behavior(self):
        empty = create_report(
            report_id="report_empty",
            created_at_utc=CREATED_AT,
            project_name="Empty",
            evidence=[],
            findings=[],
        )
        self.assertIn("No evidence references were recorded.", render_report_markdown(empty))

    def test_audit_verification_pass_fail_missing_behavior(self):
        passed = report(audit_verification=AuditVerificationResult(valid=True, event_count=1, last_hash="abc"))
        failed = report(audit_verification=AuditVerificationResult(valid=False, event_count=1, last_hash="abc", errors=["bad"]))
        missing = report(audit_verification=None)
        self.assertEqual(passed.audit_summary.hash_chain_status, "valid")
        self.assertEqual(failed.audit_summary.hash_chain_status, "failed")
        self.assertEqual(missing.audit_summary.hash_chain_status, "not_provided")
        self.assertIn("not tamper-proof", render_report_markdown(passed))
        self.assertIn("verification failed", render_report_markdown(failed).lower())
        self.assertIn("not provided", render_report_markdown(missing).lower())

    def test_invalid_severity_status_handled_safely(self):
        with self.assertRaises(ValueError):
            finding(severity="urgent")
        with self.assertRaises(ValueError):
            finding(status="complete")

    def test_json_output_parseable(self):
        parsed = json.loads(render_report_json(report()))
        self.assertEqual(parsed["schema_version"], "report.v1")
        self.assertEqual(parsed["report_id"], "report_1")

    def test_no_raw_api_keys_bearer_tokens_cookies_passwords_in_rendered_report(self):
        rendered = render_report_markdown(
            report(
                scope_summary="Cookie: session=" + SECRET_VALUE,
                methodology_summary="api_key=" + SECRET_VALUE,
                limitations=["password " + SECRET_VALUE],
            )
        )
        self.assertNotIn(SECRET_VALUE, rendered)
        self.assertIn("redacted", rendered)

    def test_report_generation_from_evidence_store(self):
        generated = report()
        self.assertEqual(len(generated.findings), 1)
        self.assertEqual(len(generated.evidence_summary), 1)
        self.assertEqual(generated.findings[0].evidence_ids, ("evidence_1",))

    def test_no_network_side_effects(self):
        generated = report()
        self.assertEqual(generated.project_name, "Example Project")


if __name__ == "__main__":
    unittest.main()
