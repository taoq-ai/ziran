import { ShieldCheck } from "lucide-react"
import { Link } from "react-router-dom"
import { OwaspMatrix } from "../components/compliance/OwaspMatrix"

export default function Compliance() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <ShieldCheck className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-semibold text-foreground">OWASP LLM Top 10 Compliance</h1>
      </div>

      <p className="text-sm text-muted-foreground max-w-2xl">
        Coverage matrix showing testing status across the OWASP Top 10 for Large Language Model
        Applications. Click a category to view its findings.
      </p>

      <OwaspMatrix />

      <div className="text-sm text-muted-foreground">
        <Link to="/findings" className="text-primary hover:underline">
          View all findings →
        </Link>
      </div>
    </div>
  )
}
