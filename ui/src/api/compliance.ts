import { useQuery } from "@tanstack/react-query"
import { get } from "./client"
import type { OwaspComplianceResponse } from "../types"

export function useOwaspCompliance(runId?: string) {
  const qs = runId ? `?run_id=${runId}` : ""
  return useQuery<OwaspComplianceResponse>({
    queryKey: ["owasp-compliance", runId],
    queryFn: () => get<OwaspComplianceResponse>(`/api/compliance/owasp${qs}`),
  })
}
