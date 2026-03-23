import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { useCreateRun } from "../api/runs"

export function NewRun() {
  const navigate = useNavigate()
  const createRun = useCreateRun()

  const [form, setForm] = useState({
    name: "",
    target_url: "",
    protocol: "",
    coverage_level: "standard",
    strategy: "fixed",
    concurrency: 5,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    createRun.mutate(
      {
        ...form,
        protocol: form.protocol || null,
        name: form.name || null,
      },
      {
        onSuccess: (run) => navigate(`/runs/${run.id}`),
      }
    )
  }

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">New Run</h2>

      <form
        onSubmit={handleSubmit}
        className="rounded-lg border border-border bg-bg-card p-6 max-w-2xl space-y-5"
      >
        <Field label="Name (optional)">
          <input
            type="text"
            placeholder="My scan"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            className="input"
          />
        </Field>

        <Field label="Target URL or config path">
          <input
            type="text"
            required
            placeholder="https://agent.example.com or ./targets/my-agent.yaml"
            value={form.target_url}
            onChange={(e) => setForm({ ...form, target_url: e.target.value })}
            className="input"
          />
        </Field>

        <div className="grid grid-cols-2 gap-4">
          <Field label="Protocol">
            <select
              value={form.protocol}
              onChange={(e) => setForm({ ...form, protocol: e.target.value })}
              className="input"
            >
              <option value="">Auto-detect</option>
              <option value="rest">REST</option>
              <option value="openai">OpenAI</option>
              <option value="mcp">MCP</option>
              <option value="a2a">A2A</option>
              <option value="browser">Browser</option>
            </select>
          </Field>

          <Field label="Coverage">
            <select
              value={form.coverage_level}
              onChange={(e) =>
                setForm({ ...form, coverage_level: e.target.value })
              }
              className="input"
            >
              <option value="essential">Essential</option>
              <option value="standard">Standard</option>
              <option value="comprehensive">Comprehensive</option>
            </select>
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <Field label="Strategy">
            <select
              value={form.strategy}
              onChange={(e) => setForm({ ...form, strategy: e.target.value })}
              className="input"
            >
              <option value="fixed">Fixed</option>
              <option value="adaptive">Adaptive</option>
              <option value="llm-adaptive">LLM Adaptive</option>
            </select>
          </Field>

          <Field label="Concurrency">
            <input
              type="number"
              min={1}
              max={20}
              value={form.concurrency}
              onChange={(e) =>
                setForm({ ...form, concurrency: Number(e.target.value) })
              }
              className="input"
            />
          </Field>
        </div>

        <div className="flex gap-3 pt-2">
          <button
            type="submit"
            disabled={createRun.isPending || !form.target_url}
            className="px-5 py-2 rounded-md bg-accent text-bg-primary text-sm font-medium hover:bg-accent-hover transition-colors disabled:opacity-50"
          >
            {createRun.isPending ? "Starting..." : "Start Scan"}
          </button>
          <button
            type="button"
            onClick={() => navigate("/")}
            className="px-5 py-2 rounded-md border border-border text-sm text-text-secondary hover:text-text-primary transition-colors"
          >
            Cancel
          </button>
        </div>

        {createRun.isError && (
          <p className="text-sm text-red-400">
            Error: {createRun.error.message}
          </p>
        )}
      </form>
    </div>
  )
}

function Field({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <label className="block">
      <span className="text-sm text-text-secondary mb-1 block">{label}</span>
      {children}
    </label>
  )
}
