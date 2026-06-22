import { ChevronLeft, ChevronRight } from "lucide-react"

interface Props {
  /** Phase labels in order (phase_index ascending). */
  phaseLabels: string[]
  /** Current stop (0-based phase index). */
  value: number
  onChange: (index: number) => void
}

/**
 * Steps the knowledge graph through its per-phase snapshots so the analyst
 * watches the campaign grow phase by phase (spec 026 US3). Rendered only when
 * a run actually carries per-phase snapshots.
 */
export function PhaseScrubber({ phaseLabels, value, onChange }: Props) {
  if (phaseLabels.length < 2) return null
  const last = phaseLabels.length - 1
  const clamp = (i: number) => Math.max(0, Math.min(last, i))

  return (
    <div className="flex items-center gap-3 px-3 py-2 border-t border-border bg-bg-tertiary">
      <span className="text-xs text-fg-secondary shrink-0">Timeline</span>
      <button
        onClick={() => onChange(clamp(value - 1))}
        disabled={value === 0}
        className="p-0.5 rounded disabled:opacity-30 hover:bg-bg-secondary"
        title="Previous phase"
      >
        <ChevronLeft className="h-4 w-4" />
      </button>
      <input
        type="range"
        min={0}
        max={last}
        step={1}
        value={value}
        onChange={(e) => onChange(clamp(Number(e.target.value)))}
        className="flex-1 accent-accent"
        aria-label="Phase timeline"
      />
      <button
        onClick={() => onChange(clamp(value + 1))}
        disabled={value === last}
        className="p-0.5 rounded disabled:opacity-30 hover:bg-bg-secondary"
        title="Next phase"
      >
        <ChevronRight className="h-4 w-4" />
      </button>
      <span className="text-xs text-fg-primary tabular-nums shrink-0 w-40 text-right capitalize" aria-live="polite">
        {value + 1}/{phaseLabels.length} · {phaseLabels[value]?.replace(/_/g, " ")}
      </span>
    </div>
  )
}
