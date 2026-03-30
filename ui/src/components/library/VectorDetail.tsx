import type { VectorDetail as VectorDetailType } from "../../types"
import { SeverityBadge } from "../findings/SeverityBadge"

interface Props {
  vector: VectorDetailType
}

export function VectorDetail({ vector }: Props) {
  return (
    <div className="p-4 bg-bg-tertiary rounded-b-lg border-t border-border space-y-4">
      {vector.description && (
        <div>
          <h4 className="text-xs font-medium text-fg-secondary mb-1">Description</h4>
          <p className="text-sm text-fg-primary">{vector.description}</p>
        </div>
      )}

      {vector.owasp_mapping.length > 0 && (
        <div>
          <h4 className="text-xs font-medium text-fg-secondary mb-1">OWASP Mapping</h4>
          <div className="flex flex-wrap gap-1">
            {vector.owasp_mapping.map((m) => (
              <span key={m} className="px-2 py-0.5 rounded bg-accent/10 text-accent text-xs">{m}</span>
            ))}
          </div>
        </div>
      )}

      {vector.references.length > 0 && (
        <div>
          <h4 className="text-xs font-medium text-fg-secondary mb-1">References</h4>
          <ul className="space-y-0.5">
            {vector.references.map((ref, i) => (
              <li key={i} className="text-xs text-accent truncate">{ref}</li>
            ))}
          </ul>
        </div>
      )}

      {vector.prompts.length > 0 && (
        <div>
          <h4 className="text-xs font-medium text-fg-secondary mb-2">
            Prompt Templates ({vector.prompts.length})
          </h4>
          <div className="space-y-3">
            {vector.prompts.map((p, i) => (
              <div key={i} className="rounded border border-border bg-bg-secondary p-3">
                <pre className="text-xs text-fg-primary whitespace-pre-wrap break-words font-mono">
                  {p.template}
                </pre>
                {Object.keys(p.variables).length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {Object.entries(p.variables).map(([k, v]) => (
                      <span key={k} className="px-1.5 py-0.5 rounded bg-bg-tertiary text-[10px] text-fg-secondary">
                        {k}={v}
                      </span>
                    ))}
                  </div>
                )}
                {p.success_indicators.length > 0 && (
                  <div className="mt-2 flex items-center gap-1">
                    <SeverityBadge severity="critical" />
                    <span className="text-[10px] text-fg-secondary">
                      Success: {p.success_indicators.join(", ")}
                    </span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
