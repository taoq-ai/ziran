import { useNavigate } from "react-router-dom"
import { useOwaspCompliance } from "../../api/compliance"
import type { OwaspCategoryStatus } from "../../types"

interface OwaspMatrixProps {
  runId?: string
}

const STATUS_STYLES: Record<string, string> = {
  critical: "bg-red-500/15 border-red-500/30 hover:bg-red-500/25",
  warning: "bg-orange-500/15 border-orange-500/30 hover:bg-orange-500/25",
  pass: "bg-green-500/15 border-green-500/30 hover:bg-green-500/25",
  not_tested: "bg-zinc-500/10 border-zinc-500/20 hover:bg-zinc-500/20",
}

const STATUS_TEXT: Record<string, string> = {
  critical: "text-red-400",
  warning: "text-orange-400",
  pass: "text-green-400",
  not_tested: "text-zinc-500",
}

function CategoryCell({ category }: { category: OwaspCategoryStatus }) {
  const navigate = useNavigate()

  return (
    <button
      onClick={() => navigate(`/findings?owasp=${category.control_id}`)}
      className={`rounded-lg border p-4 text-left transition-colors ${STATUS_STYLES[category.status] ?? STATUS_STYLES.not_tested}`}
      title={category.description}
    >
      <div className="flex items-center justify-between mb-1">
        <span className={`text-sm font-bold ${STATUS_TEXT[category.status] ?? STATUS_TEXT.not_tested}`}>
          {category.control_id}
        </span>
        {category.finding_count > 0 && (
          <span className="inline-flex items-center rounded-full bg-background/50 px-2 py-0.5 text-xs font-medium text-foreground">
            {category.finding_count}
          </span>
        )}
      </div>
      <div className="text-xs text-foreground/80 leading-tight">
        {category.control_name}
      </div>
      {category.status === "not_tested" && (
        <div className="text-xs text-zinc-500 mt-1">Not Tested</div>
      )}
    </button>
  )
}

export function OwaspMatrix({ runId }: OwaspMatrixProps) {
  const { data, isLoading } = useOwaspCompliance(runId)

  if (isLoading) {
    return <div className="text-muted-foreground text-sm">Loading compliance data...</div>
  }

  if (!data) return null

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="flex gap-6 text-sm">
        <span className="text-muted-foreground">
          Tested: <span className="text-foreground font-medium">{data.summary.tested}/10</span>
        </span>
        <span className="text-muted-foreground">
          With findings: <span className="text-foreground font-medium">{data.summary.with_findings}</span>
        </span>
        {data.summary.with_critical > 0 && (
          <span className="text-red-400">
            Critical: <span className="font-medium">{data.summary.with_critical}</span>
          </span>
        )}
      </div>

      {/* 2x5 Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {data.categories.map((category) => (
          <CategoryCell key={category.control_id} category={category} />
        ))}
      </div>
    </div>
  )
}
