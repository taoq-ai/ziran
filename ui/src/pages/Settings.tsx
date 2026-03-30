import { useState } from "react"
import { Plus, Trash2 } from "lucide-react"
import { useConfigs, useCreateConfig, useDeleteConfig } from "../api/configs"
import type { ConfigPreset } from "../types"

export function Settings() {
  const { data: presets, isLoading } = useConfigs()
  const createConfig = useCreateConfig()
  const deleteConfig = useDeleteConfig()
  const [showForm, setShowForm] = useState(false)
  const [formName, setFormName] = useState("")
  const [formDesc, setFormDesc] = useState("")
  const [formConfig, setFormConfig] = useState("{}")
  const [error, setError] = useState("")

  const handleCreate = () => {
    setError("")
    try {
      const config = JSON.parse(formConfig)
      createConfig.mutate(
        { name: formName, description: formDesc || undefined, config },
        {
          onSuccess: () => {
            setShowForm(false)
            setFormName("")
            setFormDesc("")
            setFormConfig("{}")
          },
          onError: (err) => setError(String(err)),
        }
      )
    } catch {
      setError("Invalid JSON in config field")
    }
  }

  const handleDelete = (id: string, name: string) => {
    if (confirm(`Delete preset "${name}"?`)) {
      deleteConfig.mutate(id)
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-semibold text-fg-primary">Settings</h2>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 rounded-lg bg-accent text-bg-primary px-4 py-2 text-sm font-medium hover:bg-accent-hover transition-colors"
        >
          <Plus className="h-4 w-4" />
          New Preset
        </button>
      </div>

      {/* Create form */}
      {showForm && (
        <div className="rounded-lg border border-border bg-bg-secondary p-4 mb-6">
          <h3 className="text-sm font-medium text-fg-primary mb-3">Create Preset</h3>
          <div className="space-y-3">
            <input
              type="text"
              value={formName}
              onChange={(e) => setFormName(e.target.value)}
              placeholder="Preset name"
              className="w-full bg-bg-tertiary border border-border rounded-lg px-3 py-2 text-sm text-fg-primary"
            />
            <input
              type="text"
              value={formDesc}
              onChange={(e) => setFormDesc(e.target.value)}
              placeholder="Description (optional)"
              className="w-full bg-bg-tertiary border border-border rounded-lg px-3 py-2 text-sm text-fg-primary"
            />
            <textarea
              value={formConfig}
              onChange={(e) => setFormConfig(e.target.value)}
              placeholder='{"coverage_level": "standard", "strategy": "sequential"}'
              rows={4}
              className="w-full bg-bg-tertiary border border-border rounded-lg px-3 py-2 text-sm text-fg-primary font-mono"
            />
            {error && <p className="text-xs text-severity-danger">{error}</p>}
            <div className="flex gap-2">
              <button
                onClick={handleCreate}
                disabled={!formName.trim()}
                className="rounded-lg bg-accent text-bg-primary px-4 py-2 text-sm font-medium hover:bg-accent-hover transition-colors disabled:opacity-50"
              >
                Create
              </button>
              <button
                onClick={() => setShowForm(false)}
                className="rounded-lg border border-border px-4 py-2 text-sm text-fg-secondary hover:text-fg-primary transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Presets list */}
      {isLoading ? (
        <div className="text-center text-fg-secondary py-10">Loading presets...</div>
      ) : presets && presets.length > 0 ? (
        <div className="space-y-3">
          {presets.map((preset: ConfigPreset) => (
            <div
              key={preset.id}
              className="rounded-lg border border-border bg-bg-secondary p-4 flex items-start justify-between"
            >
              <div>
                <p className="font-medium text-fg-primary">{preset.name}</p>
                {preset.description && (
                  <p className="text-sm text-fg-secondary mt-0.5">{preset.description}</p>
                )}
                <p className="text-xs text-fg-secondary mt-2">
                  Created {new Date(preset.created_at).toLocaleDateString()}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDelete(preset.id, preset.name)}
                  className="p-1.5 rounded hover:bg-severity-danger/10 transition-colors"
                  title="Delete preset"
                >
                  <Trash2 className="h-4 w-4 text-severity-danger" />
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="rounded-lg border border-border bg-bg-secondary p-10 text-center">
          <p className="text-fg-secondary">No presets yet.</p>
          <p className="text-sm text-fg-secondary mt-1">
            Create a preset to save scan configurations for reuse.
          </p>
        </div>
      )}
    </div>
  )
}
