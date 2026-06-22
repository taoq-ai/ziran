import { useState } from "react"
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  Download,
  Shield,
  XCircle,
} from "lucide-react"
import { useParams } from "react-router-dom"
import { useCancelRun, useRun } from "../api/runs"
import { downloadRunMarkdown, downloadRunYaml } from "../api/export"
import { OwaspMatrix } from "../components/compliance/OwaspMatrix"
import { KnowledgeGraph } from "../components/graph/KnowledgeGraph"
import { PhaseScrubber } from "../components/graph/PhaseScrubber"
import { AttackLogPanel, type AttackResult } from "../components/run/AttackLogPanel"
import type { GraphState } from "../types"
import { useRunProgress } from "../hooks/useWebSocket"
import type { RunStatus } from "../types"

function extractAttackResults(result: Record<string, unknown> | null): AttackResult[] {
  const raw = result?.attack_results
  return Array.isArray(raw) ? (raw as AttackResult[]) : []
}

function extractAttackPaths(result: Record<string, unknown> | null): string[][] {
  const raw = result?.critical_paths
  return Array.isArray(raw) ? (raw as string[][]) : []
}

const statusIcons: Record<RunStatus, React.ReactNode> = {
  pending: <Clock className="h-5 w-5 text-severity-warning-yellow" />,
  running: <Clock className="h-5 w-5 text-accent animate-spin" />,
  completed: <CheckCircle className="h-5 w-5 text-severity-safe" />,
  failed: <XCircle className="h-5 w-5 text-severity-danger" />,
  cancelled: <XCircle className="h-5 w-5 text-severity-muted" />,
}

export function RunDetail() {
  const { id } = useParams<{ id: string }>()
  const { data: run, isLoading } = useRun(id!)
  const { latest } = useRunProgress(
    run?.status === "running" ? id : undefined
  )
  const cancelRun = useCancelRun()
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  // null => show the final end-state; a number => that phase's snapshot.
  const [scrubIndex, setScrubIndex] = useState<number | null>(null)

  if (isLoading) {
    return <div className="text-center text-fg-secondary py-10">Loading...</div>
  }

  if (!run) {
    return <div className="text-center text-fg-secondary py-10">Run not found</div>
  }

  const finalGraph = run.graph_state_json as unknown as GraphState | null
  const orderedPhases = [...run.phase_results].sort((a, b) => a.phase_index - b.phase_index)
  const phaseSnapshots = orderedPhases.map((p) => p.graph_state_json ?? null)
  // Only offer temporal scrubbing when the run actually carries per-phase
  // snapshots (older runs fall back to the final state only).
  const hasSnapshots = phaseSnapshots.some((s) => (s?.nodes?.length ?? 0) > 0)
  const lastStop = orderedPhases.length - 1
  const activeStop = scrubIndex ?? lastStop
  // Nearest non-null snapshot at/before the active stop, else the final state.
  const displayedGraph = ((): GraphState | null => {
    if (!hasSnapshots || scrubIndex === null) return finalGraph
    for (let i = activeStop; i >= 0; i--) {
      if (phaseSnapshots[i]?.nodes?.length) return phaseSnapshots[i]
    }
    return finalGraph
  })()

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold text-fg-primary">
            {run.name ?? "Scan Results"}
          </h2>
          <p className="text-sm text-fg-secondary mt-1">{run.target_agent}</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-2 text-sm capitalize">
            {statusIcons[run.status]}
            {run.status}
          </span>
          {run.status === "running" && (
            <button
              onClick={() => cancelRun.mutate(id!)}
              className="px-3 py-1.5 rounded-md border border-severity-danger/30 text-severity-danger text-sm hover:bg-severity-danger/10 transition-colors"
            >
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Card label="Vulnerabilities" value={String(run.total_vulnerabilities)}>
          <AlertTriangle className="h-4 w-4 text-severity-danger" />
        </Card>
        <Card label="Critical Paths" value={String(run.critical_paths_count)}>
          <AlertTriangle className="h-4 w-4 text-severity-warning-orange" />
        </Card>
        <Card
          label="Trust Score"
          value={
            run.final_trust_score !== null
              ? `${(run.final_trust_score * 100).toFixed(0)}%`
              : "—"
          }
        >
          <Shield className="h-4 w-4 text-severity-safe" />
        </Card>
        <Card label="Tokens" value={run.total_tokens.toLocaleString()}>
          <Clock className="h-4 w-4 text-accent" />
        </Card>
      </div>

      {/* Live progress */}
      {run.status === "running" && latest && (
        <div className="rounded-lg border border-blue-500/30 bg-blue-500/5 p-4 mb-6">
          <p className="text-sm text-blue-300">
            <span className="font-medium">
              Phase {latest.phase_index + 1}/{latest.total_phases}
            </span>
            {latest.phase && ` — ${latest.phase}`}
            {latest.total_attacks > 0 && (
              <span className="ml-2 text-fg-secondary">
                Attack {latest.attack_index + 1}/{latest.total_attacks}
              </span>
            )}
          </p>
          {latest.attack_name && (
            <p className="text-xs text-fg-secondary mt-1">{latest.attack_name}</p>
          )}
          {latest.total_attacks > 0 && (
            <div className="mt-2 h-1.5 rounded-full bg-bg-secondary overflow-hidden">
              <div
                className="h-full bg-accent rounded-full transition-all duration-300"
                style={{
                  width: `${((latest.attack_index + 1) / latest.total_attacks) * 100}%`,
                }}
              />
            </div>
          )}
        </div>
      )}

      {/* Phase results */}
      {run.phase_results.length > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-medium mb-3">Phases</h3>
          <div className="space-y-2">
            {run.phase_results.map((phase) => (
              <div
                key={phase.id}
                className="flex items-center justify-between rounded-lg border border-border bg-bg-secondary px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  {phase.success ? (
                    <CheckCircle className="h-4 w-4 text-severity-safe" />
                  ) : (
                    <XCircle className="h-4 w-4 text-severity-danger" />
                  )}
                  <span className="text-sm capitalize">
                    {phase.phase.replace(/_/g, " ")}
                  </span>
                </div>
                <div className="flex items-center gap-6 text-sm text-fg-secondary">
                  <span>Trust: {(phase.trust_score * 100).toFixed(0)}%</span>
                  <span>{phase.duration_seconds.toFixed(1)}s</span>
                  <span>
                    {phase.vulnerabilities_found.length} vuln
                    {phase.vulnerabilities_found.length !== 1 ? "s" : ""}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Knowledge Graph */}
      {finalGraph && (
        <div className="mb-6 relative">
          <h3 className="text-lg font-medium mb-3">Knowledge Graph</h3>
          <KnowledgeGraph
            graphState={displayedGraph}
            attackPaths={extractAttackPaths(run.result_json)}
            selectedNodeId={selectedNodeId}
            onNodeSelect={(nodeId) => {
              setSelectedNodeId(nodeId)
              if (nodeId) {
                document
                  .getElementById(`attack-${nodeId}`)
                  ?.scrollIntoView({ behavior: "smooth", block: "center" })
              }
            }}
          />
          {hasSnapshots && (
            <PhaseScrubber
              phaseLabels={orderedPhases.map((p) => p.phase)}
              value={activeStop}
              onChange={setScrubIndex}
            />
          )}
        </div>
      )}

      {/* Attack log — cross-linked with the graph */}
      {extractAttackResults(run.result_json).length > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-medium mb-3">Attack Log</h3>
          <AttackLogPanel
            results={extractAttackResults(run.result_json)}
            selectedNodeId={selectedNodeId}
            onSelect={setSelectedNodeId}
          />
        </div>
      )}

      {/* OWASP Compliance Matrix */}
      {run.status === "completed" && (
        <div className="mb-6">
          <h3 className="text-lg font-medium mb-3">OWASP LLM Top 10 Coverage</h3>
          <OwaspMatrix runId={id} />
        </div>
      )}

      {/* Export buttons */}
      {run.status === "completed" && (
        <div className="flex gap-2 mb-6">
          <button
            onClick={() => downloadRunYaml(id!)}
            className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent/10 transition-colors"
          >
            <Download className="h-4 w-4" />
            Export YAML
          </button>
          <button
            onClick={() => downloadRunMarkdown(id!)}
            className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent/10 transition-colors"
          >
            <Download className="h-4 w-4" />
            Export Markdown
          </button>
        </div>
      )}

      {/* Error */}
      {run.error && (
        <div className="rounded-lg border border-severity-danger/30 bg-severity-danger/5 p-4">
          <p className="text-sm text-severity-danger font-medium">Error</p>
          <p className="text-sm text-fg-secondary mt-1">{run.error}</p>
        </div>
      )}
    </div>
  )
}

function Card({
  label,
  value,
  children,
}: {
  label: string
  value: string
  children: React.ReactNode
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-fg-secondary">{label}</p>
        {children}
      </div>
      <p className="text-xl font-bold mt-1">{value}</p>
    </div>
  )
}
