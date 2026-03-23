import { Shield } from "lucide-react"

export function Dashboard() {
  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">Dashboard</h2>

      <div className="grid grid-cols-3 gap-4 mb-8">
        {["Total Runs", "Vulnerabilities Found", "Avg Resilience Score"].map(
          (label) => (
            <div
              key={label}
              className="rounded-lg border border-border bg-bg-card p-5"
            >
              <p className="text-sm text-text-muted">{label}</p>
              <p className="text-2xl font-bold mt-1 text-text-primary">—</p>
            </div>
          )
        )}
      </div>

      <div className="rounded-lg border border-border bg-bg-card p-10 flex flex-col items-center justify-center text-center">
        <Shield className="h-12 w-12 text-text-muted mb-4" />
        <h3 className="text-lg font-medium text-text-primary">
          No scans yet
        </h3>
        <p className="text-sm text-text-muted mt-1 max-w-sm">
          Run your first security scan to see results here. Use the sidebar to
          start a new run.
        </p>
      </div>
    </div>
  )
}
