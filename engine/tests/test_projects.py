import inspect
import json
import tempfile
import unittest
from pathlib import Path

from aegis_ev.projects import (
    ProjectRecord,
    ProjectWorkspaceStore,
    ScopeDefinition,
    SessionRecord,
    TargetRecord,
    create_project_record,
    create_session_record,
    create_target_record,
    validate_target_against_scope,
)


SECRET_VALUE = "not-a-real-project-token-1234567890"
VALID_FROM = "2026-01-01T00:00:00+00:00"
VALID_UNTIL = "2026-12-31T00:00:00+00:00"


def scope(**kwargs):
    payload = {
        "scope_id": "scope_demo",
        "allowlist_domains": ("portfolio.example.test",),
        "allowlist_urls": ("https://portfolio.example.test",),
        "allowlist_cidrs": (),
        "allowed_schemes": ("https",),
        "environment": "staging",
        "valid_from": VALID_FROM,
        "valid_until": VALID_UNTIL,
        "owner_attestation": "owner supplied placeholder portfolio target",
    }
    payload.update(kwargs)
    return ScopeDefinition(**payload)


def project(**kwargs):
    payload = {
        "project_id": "project_demo",
        "name": "Portfolio Demo",
        "customer_name": "Owner",
        "environment": "staging",
        "scope": scope(),
    }
    payload.update(kwargs)
    return ProjectRecord(**payload)


class ProjectTargetScopeTests(unittest.TestCase):
    def test_create_project_defaults(self):
        record = create_project_record({"name": "Example"})
        self.assertEqual(record.status, "draft")
        self.assertEqual(record.environment, "staging")
        self.assertEqual(record.targets, ())

    def test_invalid_project_status_denied(self):
        with self.assertRaises(ValueError):
            ProjectRecord(project_id="project_bad", name="Bad", status="done")

    def test_create_target_url_normalized(self):
        target = TargetRecord(target_id="target_1", target_type="url", value="HTTPS://Portfolio.Example.Test/path?token=" + SECRET_VALUE)
        self.assertEqual(target.normalized_value, "https://portfolio.example.test/path")
        self.assertNotIn(SECRET_VALUE, json.dumps(target.to_dict(), sort_keys=True))

    def test_invalid_target_type_denied(self):
        with self.assertRaises(ValueError):
            TargetRecord(target_id="target_bad", target_type="printer", value="https://portfolio.example.test")

    def test_unsupported_scheme_denied(self):
        with self.assertRaises(ValueError):
            TargetRecord(target_id="target_bad", target_type="url", value="ftp://portfolio.example.test")

    def test_empty_target_denied(self):
        with self.assertRaises(ValueError):
            TargetRecord(target_id="target_bad", target_type="url", value="")

    def test_domain_target_normalized(self):
        target = TargetRecord(target_id="target_domain", target_type="domain", value="Portfolio.Example.Test.")
        self.assertEqual(target.normalized_value, "portfolio.example.test")

    def test_cidr_target_accepted_and_invalid_cidr_denied(self):
        target = TargetRecord(target_id="target_cidr", target_type="cidr", value="192.0.2.0/24")
        self.assertEqual(target.normalized_value, "192.0.2.0/24")
        with self.assertRaises(ValueError):
            TargetRecord(target_id="target_bad_cidr", target_type="cidr", value="192.0.2.999/24")

    def test_empty_scope_does_not_allow_all(self):
        empty = scope(allowlist_domains=(), allowlist_urls=(), allowlist_cidrs=())
        result = validate_target_against_scope("https://portfolio.example.test", "url", empty, owner="Owner")
        self.assertFalse(result["in_scope"])
        self.assertEqual(result["scope_reason"], "scope_allowlist_empty")

    def test_target_in_allowlisted_domain_marked_in_scope_true(self):
        record = create_target_record({"target_type": "url", "value": "https://portfolio.example.test"}, project())
        self.assertTrue(record.in_scope)
        self.assertEqual(record.scope_reason, "allowed_by_project_scope")

    def test_out_of_scope_target_marked_denied_safely(self):
        record = create_target_record({"target_type": "url", "value": "https://evil.example.test"}, project())
        self.assertFalse(record.in_scope)
        self.assertEqual(record.scope_reason, "target_out_of_scope")

    def test_duplicate_target_behavior_returns_existing(self):
        store = ProjectWorkspaceStore()
        store.create_project(project())
        first = store.add_target("project_demo", create_target_record({"target_type": "url", "value": "https://portfolio.example.test"}, project()))
        second = store.add_target("project_demo", create_target_record({"target_type": "url", "value": "https://portfolio.example.test/"}, project()))
        self.assertEqual(first.target_id, second.target_id)
        self.assertEqual(len(store.list_project_targets("project_demo")), 1)

    def test_create_session_defaults(self):
        session = create_session_record({"project_id": "project_demo"})
        self.assertEqual(session.status, "draft")
        self.assertEqual(session.project_id, "project_demo")

    def test_invalid_session_status_denied(self):
        with self.assertRaises(ValueError):
            SessionRecord(session_id="session_bad", project_id="project_demo", status="waiting")

    def test_session_does_not_store_secrets(self):
        session = SessionRecord(
            session_id="session_1",
            project_id="project_demo",
            actor="tester",
            purpose="validate " + SECRET_VALUE,
            metadata={"authorization": "Bearer " + SECRET_VALUE, "note": "safe"},
        )
        serialized = json.dumps(session.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)
        self.assertIn("redacted", serialized)

    def test_project_store_add_get_list(self):
        store = ProjectWorkspaceStore()
        record = store.create_project(project())
        self.assertEqual(store.get_project(record.project_id).name, "Portfolio Demo")
        self.assertEqual([item.project_id for item in store.list_projects()], ["project_demo"])

    def test_add_target_to_project(self):
        store = ProjectWorkspaceStore()
        store.create_project(project())
        target = store.add_target("project_demo", create_target_record({"target_type": "domain", "value": "portfolio.example.test"}, project()))
        self.assertEqual(target.normalized_value, "portfolio.example.test")
        self.assertEqual(len(store.get_project("project_demo").targets), 1)

    def test_link_import_evidence_finding_report_references(self):
        store = ProjectWorkspaceStore()
        store.create_project(project())
        store.add_import_reference("project_demo", "import_1")
        store.add_evidence_reference("project_demo", "evidence_1")
        store.add_finding_reference("project_demo", "finding_1")
        updated = store.add_report_reference("project_demo", "report_1")
        self.assertEqual(updated.imports, ("import_1",))
        self.assertEqual(updated.evidence_ids, ("evidence_1",))
        self.assertEqual(updated.finding_ids, ("finding_1",))
        self.assertEqual(updated.report_ids, ("report_1",))

    def test_policy_integration_denies_out_of_scope(self):
        result = validate_target_against_scope("https://evil.example.test", "url", scope(), owner="Owner")
        self.assertFalse(result["in_scope"])
        self.assertEqual(result["policy_decision"]["decision_code"], "target_out_of_scope")

    def test_store_json_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workspace.json"
            store = ProjectWorkspaceStore()
            store.create_project(project())
            store.create_session(SessionRecord(session_id="session_1", project_id="project_demo"))
            store.export_json(path)
            loaded = ProjectWorkspaceStore.import_json(path)
            self.assertEqual(loaded.get_project("project_demo").name, "Portfolio Demo")
            self.assertEqual(loaded.get_session("session_1").project_id, "project_demo")

    def test_no_raw_secrets_in_serialized_project_session_target(self):
        record = ProjectRecord(
            project_id="project_secret",
            name="Secret Project",
            description="token " + SECRET_VALUE,
            metadata={"api_key": SECRET_VALUE},
            targets=(TargetRecord(target_id="target_secret", target_type="url", value="https://portfolio.example.test?token=" + SECRET_VALUE),),
        )
        serialized = json.dumps(record.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET_VALUE, serialized)

    def test_no_network_side_effects(self):
        import aegis_ev.projects as projects

        source = inspect.getsource(projects)
        self.assertNotIn("import requests", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("subprocess", source)


if __name__ == "__main__":
    unittest.main()
