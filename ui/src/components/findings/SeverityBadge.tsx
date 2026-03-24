import { Badge } from "../ui/badge"
import type { Severity } from "../../types"

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-teal-500/20 text-teal-400 border-teal-500/30",
  info: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant="outline" className={SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </Badge>
  )
}
