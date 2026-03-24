import { Search } from "lucide-react"
import { useState } from "react"

interface FindingFiltersProps {
  onFilterChange: (filters: Record<string, string>) => void
}

const SEVERITY_OPTIONS = ["", "critical", "high", "medium", "low", "info"]
const STATUS_OPTIONS = ["", "open", "fixed", "false_positive", "ignored"]

export function FindingFilters({ onFilterChange }: FindingFiltersProps) {
  const [filters, setFilters] = useState<Record<string, string>>({})

  const updateFilter = (key: string, value: string) => {
    const updated = { ...filters, [key]: value }
    if (!value) delete updated[key]
    setFilters(updated)
    onFilterChange(updated)
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="relative flex-1 min-w-[200px]">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <input
          type="text"
          placeholder="Search findings..."
          className="w-full rounded-md border border-border bg-background pl-9 pr-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          onChange={(e) => updateFilter("search", e.target.value)}
        />
      </div>

      <select
        className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
        onChange={(e) => updateFilter("severity", e.target.value)}
        defaultValue=""
      >
        <option value="">All Severities</option>
        {SEVERITY_OPTIONS.filter(Boolean).map((s) => (
          <option key={s} value={s}>
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </option>
        ))}
      </select>

      <select
        className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
        onChange={(e) => updateFilter("status", e.target.value)}
        defaultValue=""
      >
        <option value="">All Statuses</option>
        {STATUS_OPTIONS.filter(Boolean).map((s) => (
          <option key={s} value={s}>
            {s.replace("_", " ").replace(/\b\w/g, (c) => c.toUpperCase())}
          </option>
        ))}
      </select>

      <select
        className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
        onChange={(e) => updateFilter("owasp", e.target.value)}
        defaultValue=""
      >
        <option value="">All OWASP</option>
        {Array.from({ length: 10 }, (_, i) => `LLM0${i + 1}`).map((cat) => (
          <option key={cat} value={cat}>
            {cat}
          </option>
        ))}
      </select>
    </div>
  )
}
