import { useState } from "react"
import { BookOpen, Search } from "lucide-react"
import { useVectors, useLibraryStats } from "../api/library"
import { VectorTable } from "../components/library/VectorTable"

export function Library() {
  const [category, setCategory] = useState("")
  const [severity, setSeverity] = useState("")
  const [search, setSearch] = useState("")

  const filters = {
    ...(category && { category }),
    ...(severity && { severity }),
    ...(search && { search }),
  }

  const { data: vectorData, isLoading } = useVectors(filters)
  const { data: stats } = useLibraryStats()

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6 text-fg-primary">Attack Library</h2>

      {/* Stats cards */}
      {stats && (
        <div className="grid grid-cols-3 gap-4 mb-6">
          <StatCard label="Total Vectors" value={stats.total_vectors} icon={<BookOpen className="h-4 w-4 text-accent" />} />
          <StatCard label="Total Prompts" value={stats.total_prompts} icon={<BookOpen className="h-4 w-4 text-severity-warning-orange" />} />
          <StatCard label="Categories" value={Object.keys(stats.by_category).length} icon={<BookOpen className="h-4 w-4 text-severity-safe" />} />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-4">
        <div className="flex items-center gap-2 bg-bg-secondary rounded-lg border border-border px-3 py-1.5 flex-1 max-w-xs">
          <Search className="h-4 w-4 text-fg-secondary" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search vectors..."
            className="bg-transparent text-sm text-fg-primary outline-none w-full"
          />
        </div>

        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="bg-bg-secondary border border-border rounded-lg px-3 py-1.5 text-sm text-fg-primary"
        >
          <option value="">All categories</option>
          {stats && Object.keys(stats.by_category).map((c) => (
            <option key={c} value={c}>{c.replace(/_/g, " ")}</option>
          ))}
        </select>

        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="bg-bg-secondary border border-border rounded-lg px-3 py-1.5 text-sm text-fg-primary"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {(category || severity || search) && (
          <button
            onClick={() => { setCategory(""); setSeverity(""); setSearch("") }}
            className="text-xs text-fg-secondary hover:text-fg-primary px-2"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="text-center text-fg-secondary py-10">Loading vectors...</div>
      ) : vectorData ? (
        <>
          <p className="text-xs text-fg-secondary mb-2">{vectorData.total} vectors</p>
          <VectorTable vectors={vectorData.vectors} />
        </>
      ) : (
        <div className="text-center text-fg-secondary py-10">Failed to load attack library.</div>
      )}
    </div>
  )
}

function StatCard({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-fg-secondary">{label}</p>
        {icon}
      </div>
      <p className="text-xl font-bold mt-1 text-fg-primary">{value}</p>
    </div>
  )
}
