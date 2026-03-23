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

export interface ConfigPreset {
  id: string
  name: string
  description: string | null
  config_json: Record<string, unknown>
  created_at: string
  updated_at: string
}
