# TASK-019 Green-Tier Tool Adapter Pack

## Purpose

The green-tier tool adapter pack defines safe capability metadata for Aegis EV tools and future local utilities. It does not execute external tools. It gives the recon planner and CLI a deterministic way to list capabilities, check local binary availability with `shutil.which`, create dry-run plans, validate argument shapes, and describe parser contracts for future outputs.

## What This Task Does

- Registers green-tier built-in capabilities for existing safe Aegis EV components:
  - safe HTTP metadata fetch
  - supplied-header analysis
  - passive technology fingerprinting
  - attack surface graph building
  - offline vulnerability intelligence mapping
- Registers planning-only local capabilities for future static/SBOM/dependency/config analysis tools.
- Produces dry-run `ToolPlan` objects with argv-list previews only.
- Rejects shell-style command strings, user-supplied executable paths, secret-bearing arguments, and unsupported actions.
- Creates audit-safe events and evidence from availability checks, dry-run plans, and parser results.
- Exposes CLI commands:
  - `list-tool-capabilities`
  - `check-tool-availability`
  - `plan-tool-action`
- Adds parser contracts and safe sample parsers for fixture-like output.

## What It Does Not Do

- It does not execute external binaries.
- It does not run scanners, crawlers, fuzzers, brute force tools, or intrusive validators.
- It does not run `httpx`, `katana`, `nuclei`, `ffuf`, or `sqlmap`.
- It does not contact live targets by itself.
- It does not install, download, or update tools.
- It does not call `--version` or any other binary subcommand.
- It does not add autonomous AI planning or verifier execution.

## Why Metadata Comes First

Adapter metadata lets Aegis EV reason about capabilities before execution exists. The planner can explain which safe component would handle a step, what impact level it has, what evidence it may produce, and why a future external utility remains disabled. This keeps tool selection auditable and policy-aware without adding live execution risk.

## Argv-List Planning

Tool plans use `argv_preview` as a JSON list, never a shell string. Raw shell commands are forbidden because they are hard to validate safely and can hide shell interpretation behavior. TASK-019 does not invoke subprocesses and does not use shell execution.

## Policy, Audit, Evidence, and Recon Planner Integration

If a tool plan has a target, it is evaluated through the existing policy layer before the plan can be marked allowed. Denied plans include structured reasons. Audit helpers emit events such as `tool_plan_created` and `tool_plan_denied` without secrets or command strings. Evidence helpers serialize redacted availability, plan, and parser-result data. The safe recon planner now attaches built-in green-tier capability IDs to matching proposed steps.

## Built-In Capabilities Available Now

- `builtin_safe_http_fetch`
- `builtin_safe_header_analysis`
- `builtin_passive_fingerprint`
- `builtin_attack_surface_graph`
- `builtin_vuln_intel_mapping`

These refer to already implemented Aegis EV safe components. TASK-019 still exposes them through dry-run planning metadata; it does not broaden runtime behavior.

## External Tools Are Planning-Only

- `local_semgrep_static_plan`
- `local_syft_sbom_plan`
- `local_grype_scan_plan`
- `local_trivy_config_plan`

Availability checks may report that a binary exists, but `safe_to_execute_now` remains false for these external tools in TASK-019. Future tasks may enable selected local-only execution under explicit policy, approval, workspace, output, and parser controls.

## Future Enablement

Future work can safely enable selected tools by adding explicit execution adapters, workspace path controls, output limits, parser hardening, policy decisions, approvals, and audit/evidence integration. Network-oriented tools remain out of scope until a separate task defines exact authorization, rate, impact, and safety boundaries.

## Not Implemented Yet

- Live external tool execution
- Crawler, scanner, or fuzzer execution
- `nuclei`, `httpx`, `katana`, `ffuf`, or `sqlmap` adapters
- AI planner/verifier execution
- UI
