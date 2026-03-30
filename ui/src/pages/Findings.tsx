import type { RowSelectionState } from "@tanstack/react-table"
import { AlertTriangle, Download } from "lucide-react"
import { useState } from "react"
import { useSearchParams } from "react-router-dom"
import { type FindingFilters as FindingFiltersType, useFindingStats, useFindings } from "../api/findings"
import { downloadFindingsCsv, downloadFindingsJson } from "../api/export"
import { BulkActions } from "../components/findings/BulkActions"
import { FindingDetail } from "../components/findings/FindingDetail"
import { FindingFilters } from "../components/findings/FindingFilters"
import { FindingsTable } from "../components/findings/FindingsTable"
import type { FindingSummary } from "../types"

export default function Findings() {
  const [searchParams] = useSearchParams()
  const initialOwasp = searchParams.get("owasp") || undefined

  const [filters, setFilters] = useState<FindingFiltersType>({
    owasp: initialOwasp,
    sort: "-created_at",
    limit: 25,
    offset: 0,
  })
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null)
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({})

  const { data, isLoading } = useFindings(filters)
  const { data: stats } = useFindingStats(filters)

  const handleFilterChange = (newFilters: Record<string, string>) => {
    setFilters((prev) => ({
      ...prev,
      ...newFilters,
      offset: 0,
    }))
  }

  const handlePageChange = (offset: number) => {
    setFilters((prev) => ({ ...prev, offset }))
  }

  const handleRowClick = (finding: FindingSummary) => {
    setSelectedFindingId(finding.id)
  }

  const selectedIds = Object.keys(rowSelection)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <AlertTriangle className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-semibold text-foreground">Findings</h1>
          {stats && (
            <span className="text-sm text-muted-foreground">({stats.total} total)</span>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => downloadFindingsCsv(filters)}
            className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent/10 transition-colors"
          >
            <Download className="h-4 w-4" />
            CSV
          </button>
          <button
            onClick={() => downloadFindingsJson(filters)}
            className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent/10 transition-colors"
          >
            <Download className="h-4 w-4" />
            JSON
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
            <div key={sev} className="rounded-md border border-border bg-card p-3">
              <div className="text-xs text-muted-foreground uppercase">{sev}</div>
              <div className="text-2xl font-bold text-foreground">
                {stats.by_severity[sev] ?? 0}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <FindingFilters onFilterChange={handleFilterChange} />

      {/* Bulk Actions */}
      <BulkActions selectedIds={selectedIds} onClearSelection={() => setRowSelection({})} />

      {/* Table */}
      {isLoading ? (
        <div className="text-center py-12 text-muted-foreground">Loading findings...</div>
      ) : (
        <FindingsTable
          findings={data?.items ?? []}
          total={data?.total ?? 0}
          limit={filters.limit ?? 25}
          offset={filters.offset ?? 0}
          onPageChange={handlePageChange}
          onRowClick={handleRowClick}
          rowSelection={rowSelection}
          onRowSelectionChange={setRowSelection}
        />
      )}

      {/* Detail Drawer */}
      {selectedFindingId && (
        <FindingDetail
          findingId={selectedFindingId}
          onClose={() => setSelectedFindingId(null)}
        />
      )}
    </div>
  )
}
