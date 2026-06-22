import { test, expect } from "@playwright/test"

function snapshot(nodeIds: string[]) {
  return {
    nodes: nodeIds.map((id) => ({ id, node_type: "tool", name: id })),
    edges: [],
    campaign_start: "2026-06-22T10:00:01Z",
    campaign_duration_seconds: 10,
    stats: { total_nodes: nodeIds.length, total_edges: 0, density: 0, node_types: {} },
  }
}

function phase(index: number, name: string, nodeIds: string[]) {
  return {
    id: `p${index}`,
    run_id: "run-graph-3",
    phase: name,
    phase_index: index,
    success: true,
    trust_score: 0.5,
    duration_seconds: 5,
    vulnerabilities_found: [],
    discovered_capabilities: [],
    error: null,
    graph_state_json: snapshot(nodeIds),
  }
}

const mockRun = {
  id: "run-graph-3",
  name: "Temporal demo",
  target_agent: "https://agent.acme.com",
  status: "completed",
  coverage_level: "standard",
  strategy: "balanced",
  total_vulnerabilities: 0,
  critical_paths_count: 0,
  dangerous_chains_count: 0,
  final_trust_score: 0.5,
  total_tokens: 100,
  created_at: "2026-06-22T10:00:00Z",
  started_at: "2026-06-22T10:00:01Z",
  completed_at: "2026-06-22T10:05:00Z",
  config_json: {},
  error: null,
  // Graph grows: reconnaissance has 1 node, execution adds a second.
  phase_results: [
    phase(0, "reconnaissance", ["tool_a"]),
    phase(1, "execution", ["tool_a", "tool_b"]),
  ],
  graph_state_json: snapshot(["tool_a", "tool_b"]),
  result_json: { critical_paths: [], attack_results: [] },
}

test.describe("Knowledge graph temporal scrubber (spec 026 US3)", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("**/api/runs/run-graph-3", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockRun) }),
    )
  })

  test("scrubs the graph through its per-phase snapshots", async ({ page }) => {
    await page.goto("/runs/run-graph-3")
    await page.waitForLoadState("networkidle")

    // The scrubber appears because the run carries per-phase snapshots.
    const scrubber = page.getByLabel("Phase timeline")
    await expect(scrubber).toBeVisible()

    // Defaults to the final phase.
    await expect(page.getByText(/2\/2 · execution/)).toBeVisible()

    // Stepping back to the first phase updates the position indicator.
    await scrubber.fill("0")
    await expect(page.getByText(/1\/2 · reconnaissance/)).toBeVisible()
  })
})
