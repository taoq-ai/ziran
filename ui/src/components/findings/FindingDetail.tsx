import { X } from "lucide-react"
import { useFinding, useUpdateFindingStatus } from "../../api/findings"
import type { FindingStatus } from "../../types"
import { SeverityBadge } from "./SeverityBadge"

interface FindingDetailProps {
  findingId: string
  onClose: () => void
}

const STATUS_OPTIONS: { value: FindingStatus; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "fixed", label: "Fixed" },
  { value: "false_positive", label: "False Positive" },
  { value: "ignored", label: "Ignored" },
]

export function FindingDetail({ findingId, onClose }: FindingDetailProps) {
  const { data: finding, isLoading } = useFinding(findingId)
  const updateStatus = useUpdateFindingStatus()

  if (isLoading || !finding) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end bg-black/50" onClick={onClose}>
        <div className="w-full max-w-2xl bg-card border-l border-border p-6 overflow-y-auto">
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/50" onClick={onClose}>
      <div
        className="w-full max-w-2xl bg-card border-l border-border p-6 overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div className="space-y-2">
            <h2 className="text-xl font-semibold text-foreground">{finding.title}</h2>
            <div className="flex items-center gap-3">
              <SeverityBadge severity={finding.severity} />
              <span className="text-sm text-muted-foreground">
                {finding.category.replace(/_/g, " ")}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-md p-1 text-muted-foreground hover:text-foreground hover:bg-accent/10"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Status Actions */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-muted-foreground mb-2">Status</label>
          <div className="flex gap-2">
            {STATUS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => updateStatus.mutate({ id: findingId, status: opt.value })}
                className={`rounded-md px-3 py-1.5 text-sm border transition-colors ${
                  finding.status === opt.value
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:text-foreground hover:border-foreground/30"
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Target */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-muted-foreground mb-1">Target</label>
          <code className="text-sm font-mono text-foreground">{finding.target_agent}</code>
        </div>

        {/* Description */}
        {finding.description && (
          <div className="mb-6">
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Description
            </label>
            <p className="text-sm text-foreground">{finding.description}</p>
          </div>
        )}

        {/* Remediation */}
        {finding.remediation && (
          <div className="mb-6">
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Remediation
            </label>
            <p className="text-sm text-foreground bg-green-500/5 border border-green-500/20 rounded-md p-3">
              {finding.remediation}
            </p>
          </div>
        )}

        {/* Attack Transcript */}
        {finding.prompt_used && (
          <div className="mb-6">
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Attack Prompt
            </label>
            <pre className="text-sm text-foreground bg-background border border-border rounded-md p-3 overflow-x-auto whitespace-pre-wrap">
              {finding.prompt_used}
            </pre>
          </div>
        )}

        {finding.agent_response && (
          <div className="mb-6">
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Agent Response
            </label>
            <pre className="text-sm text-foreground bg-background border border-border rounded-md p-3 overflow-x-auto whitespace-pre-wrap">
              {finding.agent_response}
            </pre>
          </div>
        )}

        {/* Evidence */}
        {finding.evidence && Object.keys(finding.evidence).length > 0 && (
          <div className="mb-6">
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Evidence
            </label>
            <pre className="text-sm text-foreground bg-background border border-border rounded-md p-3 overflow-x-auto">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          </div>
        )}

        {/* Compliance Mappings */}
        {finding.compliance_mappings.length > 0 && (
          <div className="mb-6">
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Compliance Mappings
            </label>
            <div className="flex flex-wrap gap-2">
              {finding.compliance_mappings.map((m) => (
                <span
                  key={`${m.framework}-${m.control_id}`}
                  className="inline-flex items-center rounded-full bg-primary/10 text-primary px-3 py-1 text-xs font-medium"
                >
                  {m.control_id}: {m.control_name}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Metadata */}
        <div className="text-xs text-muted-foreground space-y-1 border-t border-border pt-4">
          <p>ID: {finding.id}</p>
          <p>Fingerprint: {finding.fingerprint}</p>
          <p>Vector: {finding.vector_id}</p>
          <p>Detected: {new Date(finding.created_at).toLocaleString()}</p>
          {finding.status_changed_at && (
            <p>Status changed: {new Date(finding.status_changed_at).toLocaleString()}</p>
          )}
        </div>
      </div>
    </div>
  )
}
