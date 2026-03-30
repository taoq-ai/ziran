import { useState } from "react"
import {
  Bot,
  ChevronDown,
  ChevronRight,
  Cpu,
  Plus,
  Save,
  Shield,
  Trash2,
  Zap,
} from "lucide-react"
import { useConfigs, useCreateConfig, useDeleteConfig } from "../api/configs"
import type { ConfigPreset } from "../types"

// Settings are stored in localStorage (single-dev, no backend config API needed)
const STORAGE_KEY = "ziran-settings"

interface AppSettings {
  // LLM
  llmProvider: string
  llmModel: string
  llmApiKeyEnv: string
  llmBaseUrl: string
  llmTemperature: number
  llmMaxTokens: number
  // Scan defaults
  coverageLevel: string
  strategy: string
  concurrency: number
  attackTimeout: number
  phaseTimeout: number
  stopOnCritical: boolean
  qualityScoring: boolean
  // Autonomous agent
  pentestMaxIterations: number
}

const DEFAULT_SETTINGS: AppSettings = {
  llmProvider: "litellm",
  llmModel: "gpt-4o",
  llmApiKeyEnv: "OPENAI_API_KEY",
  llmBaseUrl: "",
  llmTemperature: 0.0,
  llmMaxTokens: 4096,
  coverageLevel: "standard",
  strategy: "fixed",
  concurrency: 5,
  attackTimeout: 60,
  phaseTimeout: 300,
  stopOnCritical: true,
  qualityScoring: false,
  pentestMaxIterations: 10,
}

function loadSettings(): AppSettings {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    return saved ? { ...DEFAULT_SETTINGS, ...JSON.parse(saved) } : DEFAULT_SETTINGS
  } catch {
    return DEFAULT_SETTINGS
  }
}

function saveSettings(settings: AppSettings) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
}

export function Settings() {
  const [settings, setSettings] = useState<AppSettings>(loadSettings)
  const [saved, setSaved] = useState(false)
  const [presetsOpen, setPresetsOpen] = useState(false)
  const [showPresetForm, setShowPresetForm] = useState(false)
  const [presetName, setPresetName] = useState("")
  const [presetDesc, setPresetDesc] = useState("")

  const { data: presets } = useConfigs()
  const createConfig = useCreateConfig()
  const deleteConfig = useDeleteConfig()

  const handleSave = () => {
    saveSettings(settings)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const update = (patch: Partial<AppSettings>) => {
    setSettings((prev) => ({ ...prev, ...patch }))
    setSaved(false)
  }

  const handleSavePreset = () => {
    createConfig.mutate(
      {
        name: presetName,
        description: presetDesc || undefined,
        config: {
          coverage_level: settings.coverageLevel,
          strategy: settings.strategy,
          concurrency: settings.concurrency,
          attack_timeout: settings.attackTimeout,
          phase_timeout: settings.phaseTimeout,
          stop_on_critical: settings.stopOnCritical,
        },
      },
      {
        onSuccess: () => {
          setShowPresetForm(false)
          setPresetName("")
          setPresetDesc("")
        },
      }
    )
  }

  return (
    <div className="max-w-3xl">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-semibold text-fg-primary">Settings</h2>
        <button
          onClick={handleSave}
          className="flex items-center gap-2 rounded-lg bg-accent text-bg-primary px-4 py-2 text-sm font-medium hover:bg-accent-hover transition-colors"
        >
          <Save className="h-4 w-4" />
          {saved ? "Saved!" : "Save Settings"}
        </button>
      </div>

      <div className="space-y-6">
        {/* LLM Configuration */}
        <Section
          icon={<Cpu className="h-4 w-4 text-accent" />}
          title="LLM Configuration"
          description="Configure the LLM provider for adaptive strategies and quality scoring."
        >
          <div className="grid grid-cols-2 gap-4">
            <Field label="Provider">
              <select
                value={settings.llmProvider}
                onChange={(e) => update({ llmProvider: e.target.value })}
                className="input"
              >
                <option value="litellm">LiteLLM (universal)</option>
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
              </select>
            </Field>
            <Field label="Model">
              <input
                type="text"
                value={settings.llmModel}
                onChange={(e) => update({ llmModel: e.target.value })}
                placeholder="gpt-4o"
                className="input"
              />
            </Field>
            <Field label="API Key Env Variable">
              <input
                type="text"
                value={settings.llmApiKeyEnv}
                onChange={(e) => update({ llmApiKeyEnv: e.target.value })}
                placeholder="OPENAI_API_KEY"
                className="input"
              />
              <p className="text-[10px] text-fg-secondary mt-1">
                Name of the environment variable containing your API key
              </p>
            </Field>
            <Field label="Base URL (optional)">
              <input
                type="text"
                value={settings.llmBaseUrl}
                onChange={(e) => update({ llmBaseUrl: e.target.value })}
                placeholder="https://api.openai.com/v1"
                className="input"
              />
            </Field>
            <Field label="Temperature">
              <input
                type="number"
                min={0}
                max={2}
                step={0.1}
                value={settings.llmTemperature}
                onChange={(e) => update({ llmTemperature: Number(e.target.value) })}
                className="input"
              />
            </Field>
            <Field label="Max Tokens">
              <input
                type="number"
                min={256}
                max={128000}
                step={256}
                value={settings.llmMaxTokens}
                onChange={(e) => update({ llmMaxTokens: Number(e.target.value) })}
                className="input"
              />
            </Field>
          </div>
        </Section>

        {/* Scan Defaults */}
        <Section
          icon={<Shield className="h-4 w-4 text-accent" />}
          title="Default Scan Settings"
          description="Defaults used when starting a new scan. Can be overridden per-run."
        >
          <div className="grid grid-cols-2 gap-4">
            <Field label="Coverage Level">
              <select
                value={settings.coverageLevel}
                onChange={(e) => update({ coverageLevel: e.target.value })}
                className="input"
              >
                <option value="essential">Essential (critical only)</option>
                <option value="standard">Standard (critical + high)</option>
                <option value="comprehensive">Comprehensive (all)</option>
              </select>
            </Field>
            <Field label="Strategy">
              <select
                value={settings.strategy}
                onChange={(e) => update({ strategy: e.target.value })}
                className="input"
              >
                <option value="fixed">Fixed (sequential phases)</option>
                <option value="adaptive">Adaptive (rule-based)</option>
                <option value="llm-adaptive">LLM Adaptive (AI-driven)</option>
              </select>
            </Field>
            <Field label="Concurrency">
              <input
                type="number"
                min={1}
                max={20}
                value={settings.concurrency}
                onChange={(e) => update({ concurrency: Number(e.target.value) })}
                className="input"
              />
              <p className="text-[10px] text-fg-secondary mt-1">
                Max parallel attacks per phase
              </p>
            </Field>
            <Field label="Attack Timeout (seconds)">
              <input
                type="number"
                min={5}
                max={600}
                value={settings.attackTimeout}
                onChange={(e) => update({ attackTimeout: Number(e.target.value) })}
                className="input"
              />
            </Field>
            <Field label="Phase Timeout (seconds)">
              <input
                type="number"
                min={30}
                max={3600}
                value={settings.phaseTimeout}
                onChange={(e) => update({ phaseTimeout: Number(e.target.value) })}
                className="input"
              />
            </Field>
            <div className="flex flex-col gap-3 pt-6">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.stopOnCritical}
                  onChange={(e) => update({ stopOnCritical: e.target.checked })}
                  className="rounded border-border"
                />
                <span className="text-sm text-fg-primary">Stop on critical finding</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.qualityScoring}
                  onChange={(e) => update({ qualityScoring: e.target.checked })}
                  className="rounded border-border"
                />
                <span className="text-sm text-fg-primary">Enable quality scoring</span>
              </label>
            </div>
          </div>
        </Section>

        {/* Autonomous Agent */}
        <Section
          icon={<Bot className="h-4 w-4 text-accent" />}
          title="Autonomous Pentesting Agent"
          description="Settings for the LLM-driven autonomous pentesting agent."
        >
          <div className="grid grid-cols-2 gap-4">
            <Field label="Max Iterations">
              <input
                type="number"
                min={1}
                max={100}
                value={settings.pentestMaxIterations}
                onChange={(e) => update({ pentestMaxIterations: Number(e.target.value) })}
                className="input"
              />
              <p className="text-[10px] text-fg-secondary mt-1">
                Max planner/executor/reasoner cycles before stopping
              </p>
            </Field>
          </div>
        </Section>

        {/* Scan Presets */}
        <div className="rounded-lg border border-border bg-bg-secondary overflow-hidden">
          <button
            onClick={() => setPresetsOpen(!presetsOpen)}
            className="w-full flex items-center gap-3 px-4 py-3 hover:bg-bg-tertiary/50 transition-colors"
          >
            <Zap className="h-4 w-4 text-accent" />
            <div className="flex-1 text-left">
              <h3 className="text-sm font-medium text-fg-primary">Scan Presets</h3>
              <p className="text-xs text-fg-secondary">
                Save and load scan configurations for quick reuse
              </p>
            </div>
            {presetsOpen ? (
              <ChevronDown className="h-4 w-4 text-fg-secondary" />
            ) : (
              <ChevronRight className="h-4 w-4 text-fg-secondary" />
            )}
          </button>

          {presetsOpen && (
            <div className="border-t border-border px-4 py-3 space-y-3">
              <div className="flex justify-end">
                <button
                  onClick={() => setShowPresetForm(!showPresetForm)}
                  className="flex items-center gap-1.5 text-xs text-accent hover:text-accent-hover transition-colors"
                >
                  <Plus className="h-3.5 w-3.5" />
                  Save Current as Preset
                </button>
              </div>

              {showPresetForm && (
                <div className="rounded-lg border border-border bg-bg-tertiary p-3 space-y-2">
                  <input
                    type="text"
                    value={presetName}
                    onChange={(e) => setPresetName(e.target.value)}
                    placeholder="Preset name"
                    className="w-full bg-bg-secondary border border-border rounded px-2 py-1.5 text-sm text-fg-primary"
                  />
                  <input
                    type="text"
                    value={presetDesc}
                    onChange={(e) => setPresetDesc(e.target.value)}
                    placeholder="Description (optional)"
                    className="w-full bg-bg-secondary border border-border rounded px-2 py-1.5 text-sm text-fg-primary"
                  />
                  <div className="flex gap-2">
                    <button
                      onClick={handleSavePreset}
                      disabled={!presetName.trim()}
                      className="rounded bg-accent text-bg-primary px-3 py-1 text-xs font-medium hover:bg-accent-hover disabled:opacity-50"
                    >
                      Save
                    </button>
                    <button
                      onClick={() => setShowPresetForm(false)}
                      className="rounded border border-border px-3 py-1 text-xs text-fg-secondary"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {presets && presets.length > 0 ? (
                <div className="space-y-2">
                  {presets.map((preset: ConfigPreset) => (
                    <div
                      key={preset.id}
                      className="flex items-center justify-between rounded border border-border bg-bg-tertiary px-3 py-2"
                    >
                      <div>
                        <p className="text-sm font-medium text-fg-primary">{preset.name}</p>
                        {preset.description && (
                          <p className="text-xs text-fg-secondary">{preset.description}</p>
                        )}
                      </div>
                      <button
                        onClick={() => deleteConfig.mutate(preset.id)}
                        className="p-1 rounded hover:bg-severity-danger/10"
                        title="Delete"
                      >
                        <Trash2 className="h-3.5 w-3.5 text-fg-secondary hover:text-severity-danger" />
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-fg-secondary text-center py-2">
                  No presets saved yet.
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Section({
  icon,
  title,
  description,
  children,
}: {
  icon: React.ReactNode
  title: string
  description: string
  children: React.ReactNode
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="flex items-center gap-2 mb-1">
        {icon}
        <h3 className="text-sm font-medium text-fg-primary">{title}</h3>
      </div>
      <p className="text-xs text-fg-secondary mb-4">{description}</p>
      {children}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs text-fg-secondary mb-1 block">{label}</span>
      {children}
    </label>
  )
}
