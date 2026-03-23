import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { get, post } from "./client"
import type { RunSummary, RunDetail } from "../types"

interface RunListResponse {
  items: RunSummary[]
  total: number
  limit: number
  offset: number
}

interface RunCreateRequest {
  target_url: string
  protocol?: string | null
  coverage_level?: string
  phases?: string[] | null
  strategy?: string
  concurrency?: number
  encoding?: string[] | null
  name?: string | null
}

export function useRuns(status?: string) {
  const params = new URLSearchParams()
  if (status) params.set("status", status)
  const query = params.toString()
  return useQuery<RunListResponse>({
    queryKey: ["runs", status],
    queryFn: () => get(`/api/runs${query ? `?${query}` : ""}`),
    refetchInterval: 5000,
  })
}

export function useRun(id: string) {
  return useQuery<RunDetail>({
    queryKey: ["run", id],
    queryFn: () => get(`/api/runs/${id}`),
    refetchInterval: 3000,
  })
}

export function useCreateRun() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: RunCreateRequest) =>
      post<RunSummary>("/api/runs", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["runs"] })
    },
  })
}

export function useCancelRun() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (runId: string) =>
      post<{ status: string }>(`/api/runs/${runId}/cancel`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["runs"] })
    },
  })
}
