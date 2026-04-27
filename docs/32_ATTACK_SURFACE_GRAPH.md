# TASK-016 Attack Surface Graph

TASK-016 adds a deterministic attack surface graph for supplied safe data. The graph connects projects, targets, endpoints, technologies, security controls, evidence, candidate findings, and risk hypotheses into one structured representation.

## What It Does

- Builds stable graph nodes and edges from already collected data.
- Links project, target, domain, URL, endpoint, technology, control, evidence, and risk hypothesis objects.
- Summarizes endpoints, technologies, missing controls, surface hints, evidence coverage, and candidate finding counts.
- Produces conservative priority hints.
- Converts graph summaries into evidence.
- Exposes a `build-attack-surface-graph` CLI/API command.

## What It Does Not Do

- It is not a scanner.
- It is not a crawler.
- It does not fetch assets or source maps.
- It does not execute scripts.
- It does not run external tools.
- It does not replay HAR or run Postman collections.
- It does not fuzz, brute force, exploit, or validate vulnerabilities.
- It does not require API keys.
- It does not hardcode the real portfolio URL.

## Inputs

The graph builder accepts supplied safe data:

- Project and target records.
- Endpoint inventory from OpenAPI/Postman/HAR imports.
- Safe HTTP fetch metadata.
- Header check results.
- Passive technology fingerprint results.
- Risk hypotheses.
- Evidence records.
- Candidate findings.

Invalid optional items are ignored with warnings where practical.

## Graph Semantics

Nodes include types such as:

- `project`
- `target`
- `domain`
- `url`
- `endpoint`
- `framework`
- `hosting`
- `web_server`
- `security_control`
- `missing_control`
- `admin_surface`
- `api_surface`
- `auth_surface`
- `upload_surface`
- `evidence`
- `risk_hypothesis`

Edges include relationships such as:

- `contains`
- `resolves_to`
- `redirects_to`
- `exposes`
- `uses`
- `protected_by`
- `missing_control`
- `supports_hypothesis`
- `backed_by_evidence`

IDs are stable and derived from content.

## Risk Hints Are Not Findings

Graph priority hints are triage signals only. They do not confirm exploitability or create confirmed findings. Production environment can increase priority labels, but it does not change a hypothesis into a vulnerability.

## Future AI Operator Path

The graph is the structured map future AI planning and vulnerability intelligence/RAG can use. Later tasks can compare technologies and controls against CVE/KEV/EPSS data, propose safe next steps, and choose authorized tools. Those future steps must still pass policy and approval checks.

## Portfolio Demo Path

The portfolio demo can later add this graph after safe fetch, header checks, and passive fingerprinting. The real portfolio URL must remain in ignored local input/output. Tests use placeholder domains only.

## Not Implemented Yet

- Vulnerability intelligence/RAG.
- AI planner/verifier.
- Crawler.
- Scanner.
- Active validation recipes.
- UI graph visualization.
