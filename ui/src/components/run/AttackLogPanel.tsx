// Attack-log panel cross-linked with the knowledge graph (spec 026 US2).
//
// Each successful attack corresponds to a vulnerability node whose id equals
// the attack's `vector_id`. Clicking a row focuses that node in the graph;
// when a node is focused elsewhere, the matching row is highlighted.
import { CheckCircle, XCircle } from "lucide-react"

export interface AttackResult {
  vector_id: string
  vector_name?: string
  successful?: boolean
  severity?: string
  category?: string
  owasp_mapping?: string[]
  atlas_mapping?: string[]
}

interface Props {
  results: AttackResult[]
  selectedNodeId: string | null
  onSelect: (nodeId: string | null) => void
}

export function AttackLogPanel({ results, selectedNodeId, onSelect }: Props) {
  if (results.length === 0) return null

  return (
    <div className="space-y-2">
      {results.map((r, i) => {
        const linked = r.successful === true // only successful attacks become graph nodes
        const active = selectedNodeId === r.vector_id
        return (
          <button
            key={r.vector_id || i}
            id={`attack-${r.vector_id}`}
            onClick={() => linked && onSelect(active ? null : r.vector_id)}
            aria-pressed={active}
            disabled={!linked}
            className={`w-full text-left flex items-center gap-3 rounded-lg border px-4 py-3 transition-colors ${
              active
                ? "border-accent bg-accent/10"
                : "border-border bg-bg-secondary hover:bg-bg-tertiary"
            } ${linked ? "cursor-pointer" : "cursor-default opacity-80"}`}
          >
            {r.successful ? (
              <XCircle className="h-4 w-4 text-severity-danger shrink-0" />
            ) : (
              <CheckCircle className="h-4 w-4 text-severity-safe shrink-0" />
            )}
            <div className="min-w-0 flex-1">
              <p className="text-sm text-fg-primary truncate">{r.vector_name ?? r.vector_id}</p>
              <div className="flex flex-wrap items-center gap-1.5 mt-1">
                {r.severity && (
                  <span className="text-[10px] uppercase rounded px-1.5 py-0.5 bg-bg-tertiary text-fg-secondary">
                    {r.severity}
                  </span>
                )}
                {(r.owasp_mapping ?? []).map((o) => (
                  <span key={o} className="text-[10px] rounded px-1.5 py-0.5 bg-accent/15 text-accent">
                    {o}
                  </span>
                ))}
                {(r.atlas_mapping ?? []).map((a) => (
                  <span
                    key={a}
                    className="text-[10px] rounded px-1.5 py-0.5 bg-severity-warning-orange/15 text-severity-warning-orange"
                  >
                    {a}
                  </span>
                ))}
              </div>
            </div>
            {linked && (
              <span className="text-[10px] text-fg-secondary shrink-0">
                {active ? "focused" : "show in graph →"}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
