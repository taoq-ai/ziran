import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { get, post, request } from "./client"
import type {
  BulkStatusResponse,
  FindingDetail,
  FindingListResponse,
  FindingStats,
  FindingStatus,
} from "../types"

export interface FindingFilters {
  run_id?: string
  severity?: string
  status?: string
  category?: string
  owasp?: string
  target?: string
  search?: string
  sort?: string
  limit?: number
  offset?: number
}

function buildParams(filters: FindingFilters): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value))
    }
  }
  return params.toString()
}

export function useFindings(filters: FindingFilters = {}) {
  const qs = buildParams(filters)
  return useQuery<FindingListResponse>({
    queryKey: ["findings", qs],
    queryFn: () => get<FindingListResponse>(`/api/findings${qs ? `?${qs}` : ""}`),
    refetchInterval: 10_000,
  })
}

export function useFinding(id: string | undefined) {
  return useQuery<FindingDetail>({
    queryKey: ["finding", id],
    queryFn: () => get<FindingDetail>(`/api/findings/${id}`),
    enabled: !!id,
  })
}

export function useFindingStats(filters: FindingFilters = {}) {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { sort, limit, offset, ...statsFilters } = filters
  const qs = buildParams(statsFilters)
  return useQuery<FindingStats>({
    queryKey: ["finding-stats", qs],
    queryFn: () => get<FindingStats>(`/api/findings/stats${qs ? `?${qs}` : ""}`),
  })
}

export function useUpdateFindingStatus() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: FindingStatus }) =>
      request<unknown>(`/api/findings/${id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] })
      queryClient.invalidateQueries({ queryKey: ["finding-stats"] })
    },
  })
}

export function useBulkUpdateStatus() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ findingIds, status }: { findingIds: string[]; status: FindingStatus }) =>
      post<BulkStatusResponse>("/findings/bulk-status", {
        finding_ids: findingIds,
        status,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] })
      queryClient.invalidateQueries({ queryKey: ["finding-stats"] })
    },
  })
}
