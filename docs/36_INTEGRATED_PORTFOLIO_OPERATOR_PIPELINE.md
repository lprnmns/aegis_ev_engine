# TASK-020 Integrated Portfolio Operator Pipeline

## Purpose

The integrated portfolio operator pipeline connects the existing safe built-in Aegis EV modules into one authorized, deterministic workflow for the future owner-provided portfolio demo. It turns one policy-gated metadata/header collection into evidence, candidate observations, passive technology hints, an attack surface graph, offline vulnerability intelligence matches, a safe recon plan, green-tier dry-run tool capability suggestions, and Markdown/JSON reports.

## Pipeline Stages

1. Safe HTTP metadata fetch using the existing policy-gated fetcher.
2. Safe header and configuration checks from fetched headers.
3. Passive technology fingerprinting from safe metadata and headers.
4. Attack surface graph construction from supplied project, target, evidence, header, and fingerprint data.
5. Offline vulnerability intelligence mapping from local knowledge fixtures.
6. Safe recon planning from graph, evidence, findings, and intelligence matches.
7. Green-tier tool capability suggestions and dry-run plans.
8. Evidence-backed Markdown and JSON report output.

## What It Does Not Do

- It is not a full penetration test.
- It is not a crawler, scanner, or fuzzer.
- It does not execute external tools.
- It does not execute `nuclei`, `httpx`, `katana`, `ffuf`, or `sqlmap`.
- It does not fetch linked assets, source maps, or live vulnerability feeds.
- It does not perform exploit validation or intrusive checks.
- It does not perform authenticated testing or login/session capture.
- It does not store response bodies, cookies, tokens, or raw auth material.
- It does not run autonomous LLM actions.

## Authorization and Local Inputs

Future live portfolio runs must use local ignored input such as `local/portfolio-demo-input.json`. The real portfolio URL must not be committed to source, tests, docs, or fixtures. The pipeline requires owner authorization attestation, `safe_mode: true`, a matching allowlisted domain, and policy validation before the one allowed live metadata/header collection.

Tracked examples use only `portfolio.example.test`.

## Report Behavior

Reports state that the run is an authorized owner-provided demo with one safe metadata/header collection. They include sections for:

- Technology Fingerprint Summary
- Attack Surface Summary
- Vulnerability Intelligence Summary
- Safe Recon Plan
- Green-Tier Tool Capability Suggestions
- Pipeline Limitations

Findings remain candidate or evidence-backed observations. Fingerprint and intelligence matches are hypotheses and prioritization hints, not confirmed vulnerabilities or exploitability claims.

## Evidence and Audit

The pipeline creates or links evidence for safe fetch metadata, header checks, fingerprinting, graph construction, vulnerability intelligence mapping, recon planning, tool capability suggestions, and final pipeline summary. Audit events cover start, fetch, header analysis, fingerprinting, graph, intelligence mapping, recon planning, report generation, completion, and denial/failure where applicable.

## Future Work

- External tool execution
- Crawler/scanner/fuzzer workflows
- Authenticated testing
- AI planner/verifier
- Retest workflow
- UI
