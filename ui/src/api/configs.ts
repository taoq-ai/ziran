import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { get, post, request } from "./client"
import type { ConfigPreset } from "../types"

export function useConfigs() {
  return useQuery({
    queryKey: ["configs"],
    queryFn: () => get<ConfigPreset[]>("/api/configs"),
  })
}

export function useCreateConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string; description?: string; config: Record<string, unknown> }) =>
      post<ConfigPreset>("/api/configs", data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["configs"] }),
  })
}

export function useUpdateConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string; name?: string; description?: string; config?: Record<string, unknown> }) =>
      request<ConfigPreset>(`/api/configs/${id}`, { method: "PUT", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["configs"] }),
  })
}

export function useDeleteConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      request<void>(`/api/configs/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["configs"] }),
  })
}
