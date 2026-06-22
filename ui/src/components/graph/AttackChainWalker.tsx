import { useEffect, useState } from "react"
import { ChevronLeft, ChevronRight, Footprints, X } from "lucide-react"

interface Props {
  /** Discovered attack paths (node-id sequences). */
  paths: string[][]
  /** Called as the walker moves; gives the active path and current step index. */
  onStep: (path: string[], stepIndex: number) => void
  /** Called when the walker is closed — clears any focus/dimming. */
  onExit: () => void
}

export function AttackChainWalker({ paths, onStep, onExit }: Props) {
  const [active, setActive] = useState(false)
  const [pathIdx, setPathIdx] = useState(0)
  const [stepIdx, setStepIdx] = useState(0)

  const path = paths[pathIdx] ?? []

  // Emit the current position whenever the walker is active and moves.
  useEffect(() => {
    if (active && path.length > 0) onStep(path, stepIdx)
  }, [active, pathIdx, stepIdx, path, onStep])

  if (paths.length === 0) {
    return (
      <button
        disabled
        title="No attack paths discovered for this run"
        className="flex items-center gap-1 px-2 py-1 text-xs rounded border border-border text-fg-secondary opacity-50 cursor-not-allowed"
      >
        <Footprints className="h-3.5 w-3.5" />
        Walk chain
      </button>
    )
  }

  if (!active) {
    return (
      <button
        onClick={() => {
          setActive(true)
          setStepIdx(0)
        }}
        className="flex items-center gap-1 px-2 py-1 text-xs rounded border border-border text-fg-secondary hover:bg-bg-secondary transition-colors"
        title="Step through a discovered attack path"
      >
        <Footprints className="h-3.5 w-3.5" />
        Walk chain
      </button>
    )
  }

  const atStart = stepIdx === 0
  const atEnd = stepIdx >= path.length - 1

  return (
    <div className="flex items-center gap-1 px-2 py-1 rounded border border-accent/40 bg-accent/10">
      {paths.length > 1 && (
        <select
          value={pathIdx}
          onChange={(e) => {
            setPathIdx(Number(e.target.value))
            setStepIdx(0)
          }}
          className="bg-bg-secondary border border-border rounded text-xs px-1 py-0.5 mr-1"
          title="Select attack path"
        >
          {paths.map((p, i) => (
            <option key={i} value={i}>
              Path {i + 1} ({p.length})
            </option>
          ))}
        </select>
      )}
      <button
        onClick={() => setStepIdx((i) => Math.max(0, i - 1))}
        disabled={atStart}
        className="p-0.5 rounded disabled:opacity-30 hover:bg-bg-secondary"
        title="Previous step"
      >
        <ChevronLeft className="h-4 w-4" />
      </button>
      <span className="text-xs text-fg-primary tabular-nums px-1" aria-live="polite">
        {stepIdx + 1}/{path.length}
      </span>
      <button
        onClick={() => setStepIdx((i) => Math.min(path.length - 1, i + 1))}
        disabled={atEnd}
        className="p-0.5 rounded disabled:opacity-30 hover:bg-bg-secondary"
        title="Next step"
      >
        <ChevronRight className="h-4 w-4" />
      </button>
      <button
        onClick={() => {
          setActive(false)
          onExit()
        }}
        className="p-0.5 rounded hover:bg-bg-secondary text-severity-danger ml-1"
        title="Exit walker"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}
