import { useParams } from "react-router-dom"

export function RunDetail() {
  const { id } = useParams()
  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">Run Detail</h2>
      <div className="rounded-lg border border-border bg-bg-card p-10 text-center text-text-muted">
        Run {id} — detail view coming soon.
      </div>
    </div>
  )
}
