import { useBulkUpdateStatus } from "../../api/findings"
import type { FindingStatus } from "../../types"

interface BulkActionsProps {
  selectedIds: string[]
  onClearSelection: () => void
}

const ACTIONS: { status: FindingStatus; label: string }[] = [
  { status: "fixed", label: "Mark as Fixed" },
  { status: "false_positive", label: "False Positive" },
  { status: "ignored", label: "Ignore" },
  { status: "open", label: "Reopen" },
]

export function BulkActions({ selectedIds, onClearSelection }: BulkActionsProps) {
  const bulkUpdate = useBulkUpdateStatus()

  if (selectedIds.length === 0) return null

  const handleAction = (status: FindingStatus) => {
    bulkUpdate.mutate(
      { findingIds: selectedIds, status },
      { onSuccess: () => onClearSelection() }
    )
  }

  return (
    <div className="flex items-center gap-3 rounded-md border border-primary/30 bg-primary/5 px-4 py-2">
      <span className="text-sm font-medium text-foreground">
        {selectedIds.length} selected
      </span>
      <div className="h-4 w-px bg-border" />
      {ACTIONS.map((action) => (
        <button
          key={action.status}
          onClick={() => handleAction(action.status)}
          disabled={bulkUpdate.isPending}
          className="rounded-md border border-border px-3 py-1 text-sm text-muted-foreground hover:text-foreground hover:bg-accent/10 disabled:opacity-50 transition-colors"
        >
          {action.label}
        </button>
      ))}
      <div className="flex-1" />
      <button
        onClick={onClearSelection}
        className="text-sm text-muted-foreground hover:text-foreground"
      >
        Clear
      </button>
    </div>
  )
}
