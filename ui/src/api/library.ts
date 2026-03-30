import { useQuery } from "@tanstack/react-query"
import { get } from "./client"
import type { VectorListResponse, VectorDetail, LibraryStats } from "../types"

interface VectorFilters {
  category?: string
  severity?: string
  phase?: string
  owasp?: string
  search?: string
}

export function useVectors(filters: VectorFilters = {}) {
  const params = new URLSearchParams()
  if (filters.category) params.set("category", filters.category)
  if (filters.severity) params.set("severity", filters.severity)
  if (filters.phase) params.set("phase", filters.phase)
  if (filters.owasp) params.set("owasp", filters.owasp)
  if (filters.search) params.set("search", filters.search)
  const qs = params.toString()

  return useQuery({
    queryKey: ["library", "vectors", filters],
    queryFn: () => get<VectorListResponse>(`/api/library/vectors${qs ? `?${qs}` : ""}`),
  })
}

export function useVectorDetail(vectorId: string | undefined) {
  return useQuery({
    queryKey: ["library", "vector", vectorId],
    queryFn: () => get<VectorDetail>(`/api/library/vectors/${vectorId}`),
    enabled: !!vectorId,
  })
}

export function useLibraryStats() {
  return useQuery({
    queryKey: ["library", "stats"],
    queryFn: () => get<LibraryStats>("/api/library/stats"),
  })
}
