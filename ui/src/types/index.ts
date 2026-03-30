export interface HealthResponse {
  status: string
  version: string
  database: string
}

export type RunStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"

export interface RunSummary {
  id: string
  name: string | null
  target_agent: string
  status: RunStatus
  coverage_level: string
  strategy: string
  total_vulnerabilities: number
  critical_paths_count: number
  dangerous_chains_count: number
  final_trust_score: number | null
  total_tokens: number
  created_at: string
  started_at: string | null
  completed_at: string | null
}

export interface PhaseResult {
  id: string
  run_id: string
  phase: string
  phase_index: number
  success: boolean
  trust_score: number
  duration_seconds: number
  vulnerabilities_found: string[]
  discovered_capabilities: string[]
  error: string | null
}

export interface RunDetail extends RunSummary {
  config_json: Record<string, unknown>
  result_json: Record<string, unknown> | null
  graph_state_json: Record<string, unknown> | null
  error: string | null
  phase_results: PhaseResult[]
}

export interface ProgressMessage {
  event: string
  phase: string | null
  phase_index: number
  total_phases: number
  attack_index: number
  total_attacks: number
  attack_name: string
  message: string
  extra: Record<string, unknown>
}

export interface ConfigPreset {
  id: string
  name: string
  description: string | null
  config_json: Record<string, unknown>
  created_at: string
  updated_at: string
}

// ── Findings ──────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export type FindingStatus = "open" | "fixed" | "false_positive" | "ignored"

export interface FindingSummary {
  id: string
  run_id: string
  vector_name: string
  category: string
  severity: Severity
  owasp_category: string | null
  target_agent: string
  status: FindingStatus
  title: string
  created_at: string
}

export interface ComplianceMapping {
  framework: string
  control_id: string
  control_name: string
}

export interface FindingDetail extends FindingSummary {
  fingerprint: string
  vector_id: string
  status_changed_at: string | null
  description: string | null
  remediation: string | null
  prompt_used: string | null
  agent_response: string | null
  evidence: Record<string, unknown> | null
  detection_metadata: Record<string, unknown> | null
  business_impact: string[] | null
  compliance_mappings: ComplianceMapping[]
}

export interface FindingListResponse {
  items: FindingSummary[]
  total: number
  limit: number
  offset: number
}

export interface FindingStats {
  total: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_category: Record<string, number>
  by_owasp: Record<string, number>
}

export interface BulkStatusResponse {
  updated: number
  failed: number
}

// ── Compliance ────────────────────────────────────────────────────────

export interface OwaspCategoryStatus {
  control_id: string
  control_name: string
  description: string
  finding_count: number
  by_severity: Record<string, number>
  status: "critical" | "warning" | "pass" | "not_tested"
}

export interface ComplianceSummary {
  total_categories: number
  tested: number
  not_tested: number
  with_critical: number
  with_findings: number
}

export interface OwaspComplianceResponse {
  categories: OwaspCategoryStatus[]
  summary: ComplianceSummary
}

// ── Library ──────────────────────────────────────────────────────────

export interface PromptTemplate {
  template: string
  variables: Record<string, string>
  success_indicators: string[]
  failure_indicators: string[]
}

export interface VectorSummary {
  id: string
  name: string
  category: string
  severity: string
  target_phase: string
  description: string
  tags: string[]
  owasp_mapping: string[]
  prompt_count: number
  protocol_filter: string[]
}

export interface VectorDetail extends VectorSummary {
  references: string[]
  prompts: PromptTemplate[]
}

export interface VectorListResponse {
  vectors: VectorSummary[]
  total: number
}

export interface LibraryStats {
  total_vectors: number
  total_prompts: number
  by_category: Record<string, number>
  by_severity: Record<string, number>
  by_owasp: Record<string, number>
}

// ── Graph ────────────────────────────────────────────────────────────

export interface GraphNode {
  id: string
  node_type: string
  [key: string]: unknown
}

export interface GraphEdge {
  source: string
  target: string
  edge_type: string
  [key: string]: unknown
}

export interface GraphState {
  nodes: GraphNode[]
  edges: GraphEdge[]
  campaign_start: string
  campaign_duration_seconds: number
  stats: {
    total_nodes: number
    total_edges: number
    density: number
    node_types: Record<string, number>
  }
}
