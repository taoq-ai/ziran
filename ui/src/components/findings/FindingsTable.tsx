import {
  type ColumnDef,
  type RowSelectionState,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table"
import { useMemo } from "react"
import type { FindingSummary } from "../../types"
import { SeverityBadge } from "./SeverityBadge"

interface FindingsTableProps {
  findings: FindingSummary[]
  total: number
  limit: number
  offset: number
  sort?: string
  onSortChange?: (sort: string) => void
  onPageChange: (offset: number) => void
  onRowClick: (finding: FindingSummary) => void
  rowSelection: RowSelectionState
  onRowSelectionChange: (selection: RowSelectionState) => void
}

const STATUS_LABELS: Record<string, string> = {
  open: "Open",
  fixed: "Fixed",
  false_positive: "False Positive",
  ignored: "Ignored",
}

export function FindingsTable({
  findings,
  total,
  limit,
  offset,
  sort: _sort,
  onSortChange: _onSortChange,
  onPageChange,
  onRowClick,
  rowSelection,
  onRowSelectionChange,
}: FindingsTableProps) {
  const columns: ColumnDef<FindingSummary>[] = useMemo(
    () => [
      {
        id: "select",
        header: ({ table }) => (
          <input
            type="checkbox"
            className="rounded border-border"
            checked={table.getIsAllRowsSelected()}
            onChange={table.getToggleAllRowsSelectedHandler()}
          />
        ),
        cell: ({ row }) => (
          <input
            type="checkbox"
            className="rounded border-border"
            checked={row.getIsSelected()}
            onChange={row.getToggleSelectedHandler()}
            onClick={(e) => e.stopPropagation()}
          />
        ),
        size: 40,
      },
      {
        accessorKey: "severity",
        header: "Severity",
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
        size: 100,
      },
      {
        accessorKey: "title",
        header: "Title",
        cell: ({ row }) => (
          <span className="font-medium text-foreground">{row.original.title}</span>
        ),
      },
      {
        accessorKey: "category",
        header: "Category",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-sm">
            {row.original.category.replace(/_/g, " ")}
          </span>
        ),
      },
      {
        accessorKey: "target_agent",
        header: "Target",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-sm font-mono truncate max-w-[200px] block">
            {row.original.target_agent}
          </span>
        ),
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => (
          <span
            className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
              row.original.status === "open"
                ? "bg-yellow-500/20 text-yellow-400"
                : row.original.status === "fixed"
                  ? "bg-green-500/20 text-green-400"
                  : "bg-zinc-500/20 text-zinc-400"
            }`}
          >
            {STATUS_LABELS[row.original.status] ?? row.original.status}
          </span>
        ),
        size: 120,
      },
      {
        accessorKey: "created_at",
        header: "Detected",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-sm">
            {new Date(row.original.created_at).toLocaleDateString()}
          </span>
        ),
        size: 110,
      },
    ],
    []
  )

  const table = useReactTable({
    data: findings,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (row) => row.id,
    state: { rowSelection },
    onRowSelectionChange: (updater) => {
      const next = typeof updater === "function" ? updater(rowSelection) : updater
      onRowSelectionChange(next)
    },
    enableRowSelection: true,
  })

  const currentPage = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(total / limit)

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-border overflow-hidden">
        <table className="w-full">
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-border bg-card">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider"
                    style={header.column.getSize() ? { width: header.column.getSize() } : undefined}
                  >
                    {header.isPlaceholder
                      ? null
                      : flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-12 text-center text-muted-foreground"
                >
                  No findings found. Run a scan to discover vulnerabilities.
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className="border-b border-border hover:bg-accent/5 cursor-pointer transition-colors"
                  onClick={() => onRowClick(row.original)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-4 py-3">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {total > limit && (
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>
            Showing {offset + 1}–{Math.min(offset + limit, total)} of {total} findings
          </span>
          <div className="flex gap-2">
            <button
              className="rounded-md border border-border px-3 py-1 hover:bg-accent/10 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={offset === 0}
              onClick={() => onPageChange(Math.max(0, offset - limit))}
            >
              Previous
            </button>
            <span className="flex items-center px-2">
              Page {currentPage} of {totalPages}
            </span>
            <button
              className="rounded-md border border-border px-3 py-1 hover:bg-accent/10 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={offset + limit >= total}
              onClick={() => onPageChange(offset + limit)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
