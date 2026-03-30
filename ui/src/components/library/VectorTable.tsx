import { useState } from "react"
import { ChevronDown, ChevronRight } from "lucide-react"
import type { VectorSummary, VectorDetail as VectorDetailType } from "../../types"
import { useVectorDetail } from "../../api/library"
import { SeverityBadge } from "../findings/SeverityBadge"
import { VectorDetail } from "./VectorDetail"

interface Props {
  vectors: VectorSummary[]
}

export function VectorTable({ vectors }: Props) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-bg-tertiary text-fg-secondary text-xs border-b border-border">
            <th className="w-8 px-3 py-2" />
            <th className="text-left px-3 py-2">Name</th>
            <th className="text-left px-3 py-2">Category</th>
            <th className="text-left px-3 py-2">Severity</th>
            <th className="text-left px-3 py-2">Phase</th>
            <th className="text-left px-3 py-2">OWASP</th>
            <th className="text-right px-3 py-2">Prompts</th>
          </tr>
        </thead>
        <tbody>
          {vectors.map((v) => (
            <VectorRow
              key={v.id}
              vector={v}
              isExpanded={expandedId === v.id}
              onToggle={() => setExpandedId(expandedId === v.id ? null : v.id)}
            />
          ))}
          {vectors.length === 0 && (
            <tr>
              <td colSpan={7} className="text-center py-8 text-fg-secondary">
                No vectors match your filters.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function VectorRow({
  vector,
  isExpanded,
  onToggle,
}: {
  vector: VectorSummary
  isExpanded: boolean
  onToggle: () => void
}) {
  const { data: detail } = useVectorDetail(isExpanded ? vector.id : undefined)

  return (
    <>
      <tr
        className="border-b border-border hover:bg-bg-tertiary/50 cursor-pointer transition-colors"
        onClick={onToggle}
      >
        <td className="px-3 py-2.5">
          {isExpanded ? (
            <ChevronDown className="h-3.5 w-3.5 text-fg-secondary" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5 text-fg-secondary" />
          )}
        </td>
        <td className="px-3 py-2.5 font-medium text-fg-primary">{vector.name}</td>
        <td className="px-3 py-2.5">
          <span className="px-2 py-0.5 rounded bg-accent/10 text-accent text-xs">
            {vector.category.replace(/_/g, " ")}
          </span>
        </td>
        <td className="px-3 py-2.5">
          <SeverityBadge severity={vector.severity as "critical" | "high" | "medium" | "low"} />
        </td>
        <td className="px-3 py-2.5 text-fg-secondary capitalize">{vector.target_phase.replace(/_/g, " ")}</td>
        <td className="px-3 py-2.5">
          <div className="flex flex-wrap gap-1">
            {vector.owasp_mapping.slice(0, 2).map((m) => (
              <span key={m} className="text-[10px] px-1.5 py-0.5 rounded bg-bg-tertiary text-fg-secondary">{m}</span>
            ))}
            {vector.owasp_mapping.length > 2 && (
              <span className="text-[10px] text-fg-secondary">+{vector.owasp_mapping.length - 2}</span>
            )}
          </div>
        </td>
        <td className="px-3 py-2.5 text-right text-fg-secondary">{vector.prompt_count}</td>
      </tr>
      {isExpanded && detail && (
        <tr>
          <td colSpan={7} className="p-0">
            <VectorDetail vector={detail} />
          </td>
        </tr>
      )}
    </>
  )
}
