import type {
  AIGuardrailSummary,
  ApprovalSummary,
  AttackSurfaceSummary,
  EvidenceSummary,
  FindingSummary,
  ReportSummary,
  PipelineStage,
  ProjectSummary,
  ReconStepSummary,
  RemediationSummary,
  TargetScopeSummary
} from "./types";

export const projectSummary: ProjectSummary = {
  projectName: "Portfolio Demo",
  targetUrl: "https://portfolio.example.test",
  environment: "production",
  safeMode: true,
  authorization: "owner-attested",
  liveRequestMode: "mock",
  pipelineStatus: "mock-complete",
  evidenceCount: 18,
  findingCount: 6,
  auditStatus: "valid"
};

export const targetScope: TargetScopeSummary = {
  allowedDomain: "portfolio.example.test",
  allowedSchemes: ["https"],
  environment: "production",
  attestation: "Owner attestation required before any future live run",
  outOfScopeExample: "https://api.portfolio.example.test/admin-preview",
  notes: [
    "This shell does not scan targets automatically.",
    "Real targets will be supplied later through local ignored input or a future scoped UI workflow.",
    "Out-of-scope targets remain visible as denied examples only."
  ]
};

export const pipelineStages: PipelineStage[] = [
  {
    id: "stage_fetch",
    name: "Safe fetch metadata",
    status: "mocked",
    evidenceCount: 1,
    warnings: [],
    safetyNote: "One low-impact metadata/header collection is represented as mock data."
  },
  {
    id: "stage_headers",
    name: "Header checks",
    status: "mocked",
    evidenceCount: 6,
    warnings: ["Findings are candidate observations only."],
    safetyNote: "No response body, cookies, or tokens are stored."
  },
  {
    id: "stage_fingerprint",
    name: "Passive technology fingerprint",
    status: "mocked",
    evidenceCount: 1,
    warnings: [],
    safetyNote: "Uses already supplied metadata only; no asset fetching."
  },
  {
    id: "stage_graph",
    name: "Attack surface graph",
    status: "mocked",
    evidenceCount: 1,
    warnings: [],
    safetyNote: "Graph is built from supplied safe data only."
  },
  {
    id: "stage_intel",
    name: "Vulnerability intelligence mapping",
    status: "mocked",
    evidenceCount: 2,
    warnings: ["Knowledge matches are not vulnerability confirmation."],
    safetyNote: "Offline fixture mapping only; no live feeds."
  },
  {
    id: "stage_recon",
    name: "Recon planner",
    status: "mocked",
    evidenceCount: 2,
    warnings: [],
    safetyNote: "Planning only; no tool execution."
  },
  {
    id: "stage_tools",
    name: "Green-tier tool suggestions",
    status: "mocked",
    evidenceCount: 2,
    warnings: ["External tools are planning-only."],
    safetyNote: "Dry-run capability suggestions only."
  },
  {
    id: "stage_retest",
    name: "Remediation and retest",
    status: "ready",
    evidenceCount: 3,
    warnings: ["Live retest is not wired in this UI task."],
    safetyNote: "Retest comparison uses safe supplied metadata only."
  }
];

export const findings: FindingSummary[] = [
  {
    id: "finding_missing_csp",
    title: "Missing Content-Security-Policy",
    severity: "medium",
    status: "candidate",
    verification: "evidence_backed",
    retestStatus: "not_retested",
    evidenceIds: ["evidence_header_csp"]
  },
  {
    id: "finding_clickjacking",
    title: "Missing clickjacking controls",
    severity: "medium",
    status: "candidate",
    verification: "evidence_backed",
    retestStatus: "not_retested",
    evidenceIds: ["evidence_header_clickjacking"]
  },
  {
    id: "finding_nosniff",
    title: "Missing X-Content-Type-Options: nosniff",
    severity: "low",
    status: "candidate",
    verification: "evidence_backed",
    retestStatus: "not_retested",
    evidenceIds: ["evidence_header_nosniff"]
  },
  {
    id: "finding_referrer",
    title: "Missing Referrer-Policy",
    severity: "low",
    status: "candidate",
    verification: "evidence_backed",
    retestStatus: "not_retested",
    evidenceIds: ["evidence_header_referrer"]
  },
  {
    id: "finding_permissions",
    title: "Missing Permissions-Policy",
    severity: "info",
    status: "candidate",
    verification: "evidence_backed",
    retestStatus: "not_retested",
    evidenceIds: ["evidence_header_permissions"]
  },
  {
    id: "finding_disclosure",
    title: "Technology disclosure header present",
    severity: "info",
    status: "candidate",
    verification: "evidence_backed",
    retestStatus: "inconclusive",
    evidenceIds: ["evidence_header_disclosure"]
  }
];

export const evidenceRows: EvidenceSummary[] = [
  {
    id: "evidence_fetch_metadata",
    sourceType: "safe_http_fetch",
    title: "Safe HTTP metadata fetch",
    summary: "Mock status, redirect, and response header metadata.",
    redactionApplied: true,
    bodyStored: false
  },
  {
    id: "evidence_header_csp",
    sourceType: "web_header_check",
    title: "Header check: CSP",
    summary: "Content-Security-Policy was absent in supplied metadata.",
    redactionApplied: true,
    bodyStored: false
  },
  {
    id: "evidence_fingerprint",
    sourceType: "technology_fingerprint",
    title: "Passive fingerprint",
    summary: "High-confidence framework/platform hints from safe metadata.",
    redactionApplied: true,
    bodyStored: false
  },
  {
    id: "evidence_graph",
    sourceType: "attack_surface_graph",
    title: "Attack surface graph",
    summary: "Targets, technologies, controls, and hypotheses linked to evidence.",
    redactionApplied: true,
    bodyStored: false
  },
  {
    id: "evidence_intel",
    sourceType: "vulnerability_intelligence",
    title: "Offline intelligence mapping",
    summary: "Local OWASP/CWE-style mapping for prioritization.",
    redactionApplied: true,
    bodyStored: false
  },
  {
    id: "evidence_recon",
    sourceType: "recon_planner",
    title: "Safe recon plan",
    summary: "Green-only next steps plus blocked future actions.",
    redactionApplied: true,
    bodyStored: false
  }
];

export const reportRows: ReportSummary[] = [
  {
    title: "Portfolio Operator Summary",
    format: "markdown",
    status: "mock-ready",
    path: null,
    summary: "Evidence-backed narrative only"
  },
  {
    title: "Portfolio Operator Data",
    format: "json",
    status: "mock-ready",
    path: null,
    summary: "Structured output for UI integration"
  },
  {
    title: "Audit Chain",
    format: "jsonl",
    status: "mock-valid",
    path: null,
    summary: "No PDF generation in this task"
  }
];

export const attackSurface: AttackSurfaceSummary = {
  targets: 2,
  technologies: ["Next.js", "Vercel", "HTTPS", "Web headers"],
  missingControls: ["CSP", "Permissions-Policy", "Referrer-Policy", "nosniff", "clickjacking control"],
  hypotheses: ["Missing security control overlap", "Technology disclosure review", "Safe header hardening"],
  evidenceCoverage: 10
};

export const reconSteps: ReconStepSummary[] = [
  {
    id: "recon_review_evidence",
    title: "Review evidence-backed header observations",
    impact: "green",
    status: "ready",
    rationale: "Human review before any future validation."
  },
  {
    id: "recon_generate_report",
    title: "Generate Markdown and JSON report",
    impact: "green",
    status: "ready",
    rationale: "Report from supplied evidence only."
  },
  {
    id: "recon_future_auth",
    title: "Future authenticated validation",
    impact: "amber",
    status: "requires_approval",
    rationale: "Future-only and requires explicit approval and safe design."
  },
  {
    id: "recon_intrusive",
    title: "Intrusive validation",
    impact: "red",
    status: "blocked",
    rationale: "Blocked in this product mode."
  }
];

export const remediation: RemediationSummary = {
  findingTitle: "Missing Content-Security-Policy",
  recommendedHeaders: [
    "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Frame-Options: DENY",
    "X-Content-Type-Options: nosniff",
    "Referrer-Policy: strict-origin-when-cross-origin",
    "Permissions-Policy: camera=(), microphone=(), geolocation=()"
  ],
  retestDefinitions: [
    { status: "appears_resolved", meaning: "The expected safe observation is present after remediation." },
    { status: "still_present", meaning: "The same observation is still visible in after-state metadata." },
    { status: "inconclusive", meaning: "The comparison needs human review or more authorized evidence." }
  ],
  disabledActionReason: "Live retest is disabled in the UI shell until sidecar integration is explicitly added."
};

export const approvals: ApprovalSummary[] = [
  {
    id: "approval_pending_demo",
    title: "Review amber future validation proposal",
    status: "pending",
    requester: "safe_recon_planner",
    note: "LLM and agents cannot approve their own actions."
  },
  {
    id: "approval_scope_demo",
    title: "Scope attestation accepted",
    status: "approved",
    requester: "policy_gateway",
    note: "Approval is mock-only in this shell."
  },
  {
    id: "approval_consumed_demo",
    title: "Report generation approval consumed",
    status: "consumed",
    requester: "reporting",
    note: "Consumed approvals remain auditable."
  }
];

export const aiGuardrails: AIGuardrailSummary = {
  roles: ["Planner", "Verifier", "Reporter", "Remediation Advisor", "Policy Reviewer"],
  routerMode: "mock-only",
  providerStatus: "Provider-agnostic mock router; live model calls disabled",
  validationStatus: "passing",
  notes: [
    "No API keys are required.",
    "No live model provider is called.",
    "Guardrail validation blocks unsafe or overclaiming output.",
    "Human approval remains required for amber and red actions."
  ]
};
