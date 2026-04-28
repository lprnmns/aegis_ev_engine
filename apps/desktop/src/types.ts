export type StatusTone = "good" | "info" | "warn" | "danger" | "neutral";

export interface ProjectSummary {
  projectName: string;
  targetUrl: string;
  environment: "development" | "staging" | "production";
  safeMode: boolean;
  authorization: "owner-attested" | "missing" | "expired";
  liveRequestMode: "mock" | "disabled";
  pipelineStatus: "ready" | "mock-complete" | "disabled";
  evidenceCount: number;
  findingCount: number;
  auditStatus: "valid" | "not-run";
}

export interface TargetScopeSummary {
  allowedDomain: string;
  allowedSchemes: string[];
  environment: string;
  attestation: string;
  outOfScopeExample: string;
  notes: string[];
}

export interface PipelineStage {
  id: string;
  name: string;
  status: "mocked" | "ready" | "blocked" | "disabled";
  evidenceCount: number;
  warnings: string[];
  safetyNote: string;
}

export interface FindingSummary {
  id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high";
  status: "candidate";
  verification: "evidence_backed";
  retestStatus: "not_retested" | "appears_resolved" | "still_present" | "inconclusive";
  evidenceIds: string[];
}

export interface EvidenceSummary {
  id: string;
  sourceType: string;
  title: string;
  summary: string;
  redactionApplied: boolean;
  bodyStored: boolean;
}

export interface AttackSurfaceSummary {
  targets: number;
  technologies: string[];
  missingControls: string[];
  hypotheses: string[];
  evidenceCoverage: number;
}

export interface ReconStepSummary {
  id: string;
  title: string;
  impact: "green" | "amber" | "red";
  status: "ready" | "blocked" | "requires_approval";
  rationale: string;
}

export interface RemediationSummary {
  findingTitle: string;
  recommendedHeaders: string[];
  retestDefinitions: Array<{ status: string; meaning: string }>;
  disabledActionReason: string;
}

export interface ApprovalSummary {
  id: string;
  title: string;
  status: "pending" | "approved" | "consumed";
  requester: string;
  note: string;
}

export interface AIGuardrailSummary {
  roles: string[];
  routerMode: "mock-only";
  providerStatus: string;
  validationStatus: "passing" | "not-run";
  notes: string[];
}
