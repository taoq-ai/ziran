import { Shield, AlertTriangle, Activity } from "lucide-react"
import { Link } from "react-router-dom"
import { useRuns } from "../api/runs"
import { cn } from "../lib/utils"
import type { RunStatus } from "../types"

const statusColors: Record<RunStatus, string> = {
  pending: "text-yellow-400",
  running: "text-blue-400",
  completed: "text-green-400",
  failed: "text-red-400",
  cancelled: "text-text-muted",
}

export function Dashboard() {
  const { data, isLoading } = useRuns()

  const runs = data?.items ?? []
  const totalVulns = runs.reduce((s, r) => s + r.total_vulnerabilities, 0)
  const completedRuns = runs.filter((r) => r.status === "completed")
  const avgResilience =
    completedRuns.length > 0
      ? completedRuns.reduce((s, r) => s + (r.final_trust_score ?? 0), 0) /
        completedRuns.length
      : null

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">Dashboard</h2>

      <div className="grid grid-cols-3 gap-4 mb-8">
        <StatCard
          label="Total Runs"
          value={data ? String(data.total) : "—"}
          icon={<Activity className="h-5 w-5 text-accent" />}
        />
        <StatCard
          label="Vulnerabilities Found"
          value={data ? String(totalVulns) : "—"}
          icon={<AlertTriangle className="h-5 w-5 text-red-400" />}
        />
        <StatCard
          label="Avg Resilience Score"
          value={
            avgResilience !== null
              ? `${(avgResilience * 100).toFixed(0)}%`
              : "—"
          }
          icon={<Shield className="h-5 w-5 text-green-400" />}
        />
      </div>

      {isLoading ? (
        <div className="text-center text-text-muted py-10">Loading...</div>
      ) : runs.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-card p-10 flex flex-col items-center justify-center text-center">
          <Shield className="h-12 w-12 text-text-muted mb-4" />
          <h3 className="text-lg font-medium text-text-primary">
            No scans yet
          </h3>
          <p className="text-sm text-text-muted mt-1 max-w-sm">
            Run your first security scan to see results here.
          </p>
          <Link
            to="/runs/new"
            className="mt-4 px-4 py-2 rounded-md bg-accent text-bg-primary text-sm font-medium hover:bg-accent-hover transition-colors"
          >
            Start a new run
          </Link>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-bg-secondary text-text-muted">
              <tr>
                <th className="text-left px-4 py-3 font-medium">Target</th>
                <th className="text-left px-4 py-3 font-medium">Status</th>
                <th className="text-left px-4 py-3 font-medium">Vulns</th>
                <th className="text-left px-4 py-3 font-medium">Trust</th>
                <th className="text-left px-4 py-3 font-medium">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {runs.map((run) => (
                <tr
                  key={run.id}
                  className="hover:bg-bg-secondary/50 transition-colors"
                >
                  <td className="px-4 py-3">
                    <Link
                      to={`/runs/${run.id}`}
                      className="text-accent hover:underline"
                    >
                      {run.name ?? run.target_agent}
                    </Link>
                  </td>
                  <td className={cn("px-4 py-3 capitalize", statusColors[run.status])}>
                    {run.status}
                  </td>
                  <td className="px-4 py-3">{run.total_vulnerabilities}</td>
                  <td className="px-4 py-3">
                    {run.final_trust_score !== null
                      ? `${(run.final_trust_score * 100).toFixed(0)}%`
                      : "—"}
                  </td>
                  <td className="px-4 py-3 text-text-muted">
                    {new Date(run.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function StatCard({
  label,
  value,
  icon,
}: {
  label: string
  value: string
  icon: React.ReactNode
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-card p-5">
      <div className="flex items-center justify-between">
        <p className="text-sm text-text-muted">{label}</p>
        {icon}
      </div>
      <p className="text-2xl font-bold mt-1 text-text-primary">{value}</p>
    </div>
  )
}
