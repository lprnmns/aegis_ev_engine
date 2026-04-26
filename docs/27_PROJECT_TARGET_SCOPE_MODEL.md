# TASK-011 Project, Target, Scope, and Session Model

TASK-011 adds durable workspace models for organizing authorized Web/API validation work before live testing is introduced. It is a data and contract layer only.

## Project

A project is the top-level workspace for a customer or owner-approved validation effort. It stores:

- Project identity, name, description, customer name, environment, and status.
- Optional authorization profile reference.
- Explicit project scope.
- Targets.
- References to imports, evidence, findings, reports, and audit logs.
- Tags and redacted metadata.

Project statuses are `draft`, `active`, `paused`, `completed`, and `archived`. New projects default to `draft`, not `completed`.

## Target

A target is a scoped object that may later be validated by safe Web/API workflows. Supported target types are:

- `web`
- `api`
- `domain`
- `url`
- `cidr`
- `mobile`
- `desktop`
- `unknown`

For Phase 1, `web`, `api`, `url`, and `domain` are primary. `mobile` and `desktop` exist only as model enum values and are not active test modules.

Targets store a raw display value only after redaction and a deterministic `normalized_value`. URL-like targets remove query strings during normalization so secrets in URLs are not stored.

## Scope

Scope is explicit authorization metadata for a project. It includes:

- Domain, URL, and CIDR allowlists.
- Optional denylist.
- Allowed schemes and optional allowed ports.
- Environment.
- Validity window.
- Owner attestation, notes, and tags.

An empty scope does not allow everything. Scope feeds the existing deterministic policy layer by creating an `AuthorizationProfile` for target validation. Project scope does not bypass policy denial.

## Session

A session is metadata for a planned or future validation workflow. It stores:

- Session ID and project ID.
- Actor and purpose.
- Status.
- Selected target IDs.
- Linked import, evidence, finding, approval, and report IDs.
- Redacted metadata.

Session statuses are `draft`, `ready`, `running`, `paused`, `completed`, `failed`, and `cancelled`.

Sessions do not store browser cookies, bearer tokens, API keys, passwords, raw auth material, or captured login/session data. Future authenticated workflows must store references to approved credential/session handling systems, not secrets.

## Store

The initial `ProjectWorkspaceStore` is an in-memory store with JSON file import/export. It supports:

- Create, get, list, and status update for projects.
- Add and list project targets.
- Link import, evidence, finding, and report references.
- Create, get, list, and status update for sessions.

No database dependency is added in TASK-011.

## CLI/API Contract

TASK-011 adds deterministic JSON commands:

- `create-project`
- `get-project`
- `list-projects`
- `add-target`
- `list-targets`
- `create-session`
- `get-session`
- `list-sessions`
- `update-session-status`
- `validate-project-target`
- `link-project-reference`

Commands accept JSON via stdin or `--input-file`, emit JSON, return non-zero on invalid input, and do not require API keys.

## Import, Evidence, Finding, and Report Links

Imported OpenAPI/Postman/HAR data can be linked to projects by import ID. Evidence, finding, and report IDs can also be linked to projects and sessions. TASK-011 does not create fake findings or mark anything confirmed.

Endpoint inventory from TASK-010 can be represented later as target references or target metadata when future authorized validation workflows need it.

## Portfolio Demo Readiness

The future demo target will be the owner's personal portfolio website. TASK-011 models this only with placeholders such as:

```json
{
  "target_type": "url",
  "value": "https://portfolio.example.test"
}
```

The real portfolio URL must be supplied later by the owner. TASK-011 performs no live request, fetch, crawl, or scan.

## Not Implemented Yet

- Live HTTP runner.
- Login/session capture.
- UI.
- Database persistence.
- Scanner execution.
- AI verifier.
- Portfolio URL hardcoding.
