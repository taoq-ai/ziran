import type { FindingFilters } from "./findings"

const API_BASE = "/api"

function buildExportUrl(path: string, filters?: FindingFilters): string {
  const params = new URLSearchParams()
  if (filters) {
    for (const [key, value] of Object.entries(filters)) {
      if (
        value !== undefined &&
        value !== null &&
        value !== "" &&
        key !== "sort" &&
        key !== "limit" &&
        key !== "offset"
      ) {
        params.set(key, String(value))
      }
    }
  }
  const qs = params.toString()
  return `${API_BASE}/export/${path}${qs ? `?${qs}` : ""}`
}

export function downloadFindingsCsv(filters?: FindingFilters): void {
  window.open(buildExportUrl("findings.csv", filters), "_blank")
}

export function downloadFindingsJson(filters?: FindingFilters): void {
  window.open(buildExportUrl("findings.json", filters), "_blank")
}

export function downloadRunYaml(runId: string): void {
  window.open(`${API_BASE}/export/run/${runId}.yaml`, "_blank")
}

export function downloadRunMarkdown(runId: string): void {
  window.open(`${API_BASE}/export/run/${runId}.md`, "_blank")
}
