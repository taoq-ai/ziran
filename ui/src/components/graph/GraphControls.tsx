import { Maximize2, Pause, Play, X } from "lucide-react"

import type { LayoutMode } from "./layouts"
import type { ClusterMode } from "./clustering"

interface Props {
  layoutMode: LayoutMode
  onLayoutChange: (mode: LayoutMode) => void
  clusterMode: ClusterMode
  onClusterChange: (mode: ClusterMode) => void
  hasAgents: boolean
  physicsEnabled: boolean
  onTogglePhysics: () => void
  onFit: () => void
  showClear: boolean
  onClear: () => void
}

const CLUSTER_OPTIONS: { mode: ClusterMode; label: string }[] = [
  { mode: "none", label: "No grouping" },
  { mode: "phase", label: "Group: phase" },
  { mode: "type", label: "Group: type" },
  { mode: "agent", label: "Group: agent" },
]

const LAYOUTS: { mode: LayoutMode; label: string }[] = [
  { mode: "force", label: "Force" },
  { mode: "hierarchical", label: "By Phase" },
  { mode: "centrality", label: "Centrality" },
]

export function GraphControls({
  layoutMode,
  onLayoutChange,
  clusterMode,
  onClusterChange,
  hasAgents,
  physicsEnabled,
  onTogglePhysics,
  onFit,
  showClear,
  onClear,
}: Props) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex items-center rounded border border-border overflow-hidden" role="group" aria-label="Layout mode">
        {LAYOUTS.map(({ mode, label }) => (
          <button
            key={mode}
            onClick={() => onLayoutChange(mode)}
            aria-pressed={layoutMode === mode}
            className={`px-2 py-1 text-xs transition-colors ${
              layoutMode === mode
                ? "bg-accent text-white"
                : "bg-bg-secondary text-fg-secondary hover:bg-bg-tertiary"
            }`}
          >
            {label}
          </button>
        ))}
      </div>
      <select
        value={clusterMode}
        onChange={(e) => onClusterChange(e.target.value as ClusterMode)}
        aria-label="Cluster mode"
        className="bg-bg-secondary border border-border rounded text-xs px-1.5 py-1 text-fg-secondary"
      >
        {CLUSTER_OPTIONS.filter((o) => o.mode !== "agent" || hasAgents).map(({ mode, label }) => (
          <option key={mode} value={mode}>
            {label}
          </option>
        ))}
      </select>
      <button onClick={onFit} className="p-1.5 rounded hover:bg-bg-secondary transition-colors" title="Fit view">
        <Maximize2 className="h-4 w-4 text-fg-secondary" />
      </button>
      <button
        onClick={onTogglePhysics}
        className="p-1.5 rounded hover:bg-bg-secondary transition-colors"
        title={physicsEnabled ? "Pause physics" : "Resume physics"}
      >
        {physicsEnabled ? (
          <Pause className="h-4 w-4 text-fg-secondary" />
        ) : (
          <Play className="h-4 w-4 text-fg-secondary" />
        )}
      </button>
      {showClear && (
        <button
          onClick={onClear}
          className="p-1.5 rounded hover:bg-bg-secondary transition-colors text-severity-danger"
          title="Clear highlight"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  )
}
