// Legend that doubles as a filter (spec 026 FR-009): toggle node types,
// edge types, and severity bands. All styling comes from the shared spec.
import { graphStyle } from "./graphStyle"

interface Props {
  /** Node types present in the current graph (subset of the spec's types). */
  nodeTypes: string[]
  hiddenNodeTypes: Set<string>
  onToggleNodeType: (type: string) => void
  edgeTypes: string[]
  hiddenEdgeTypes: Set<string>
  onToggleEdgeType: (type: string) => void
  severities: string[]
  hiddenSeverities: Set<string>
  onToggleSeverity: (severity: string) => void
}

function humanize(value: string): string {
  return value.replace(/_/g, " ")
}

export function GraphLegend({
  nodeTypes,
  hiddenNodeTypes,
  onToggleNodeType,
  edgeTypes,
  hiddenEdgeTypes,
  onToggleEdgeType,
  severities,
  hiddenSeverities,
  onToggleSeverity,
}: Props) {
  return (
    <div className="flex flex-col gap-2 px-3 py-2 border-t border-border bg-bg-tertiary text-[11px]">
      {nodeTypes.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="text-fg-secondary font-medium">Nodes:</span>
          {nodeTypes.map((type) => {
            const style = graphStyle.node_types[type]
            const active = !hiddenNodeTypes.has(type)
            return (
              <button
                key={type}
                onClick={() => onToggleNodeType(type)}
                aria-pressed={active}
                className={`flex items-center gap-1 capitalize transition-opacity ${active ? "opacity-100" : "opacity-40"}`}
                title={`Toggle ${humanize(type)} nodes`}
              >
                <span
                  className="inline-block w-2.5 h-2.5"
                  style={{
                    backgroundColor: style?.color ?? "#94a3b8",
                    borderRadius: style?.shape === "dot" || style?.shape === "ellipse" ? "50%" : "2px",
                  }}
                />
                {humanize(type)}
              </button>
            )
          })}
        </div>
      )}

      {edgeTypes.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="text-fg-secondary font-medium">Edges:</span>
          {edgeTypes.map((type) => {
            const style = graphStyle.edge_types[type]
            const active = !hiddenEdgeTypes.has(type)
            return (
              <button
                key={type}
                onClick={() => onToggleEdgeType(type)}
                aria-pressed={active}
                className={`flex items-center gap-1 transition-opacity ${active ? "opacity-100" : "opacity-40"}`}
                title={`Toggle ${humanize(type)} edges`}
              >
                <span
                  className="inline-block w-3 h-0.5"
                  style={{ backgroundColor: style?.color ?? "#94a3b8" }}
                />
                {humanize(type)}
              </button>
            )
          })}
        </div>
      )}

      {severities.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="text-fg-secondary font-medium">Severity:</span>
          {severities.map((severity) => {
            const active = !hiddenSeverities.has(severity)
            return (
              <button
                key={severity}
                onClick={() => onToggleSeverity(severity)}
                aria-pressed={active}
                className={`flex items-center gap-1 capitalize transition-opacity ${active ? "opacity-100" : "opacity-40"}`}
                title={`Toggle ${severity} severity nodes`}
              >
                <span
                  className="inline-block w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: graphStyle.severity_ramp[severity] ?? "#94a3b8" }}
                />
                {severity}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
