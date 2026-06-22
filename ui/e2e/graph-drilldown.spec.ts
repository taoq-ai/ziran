import { test, expect } from "@playwright/test"

const mockRun = {
  id: "run-graph-2",
  name: "Drill-down demo",
  target_agent: "https://agent.acme.com",
  status: "completed",
  coverage_level: "standard",
  strategy: "balanced",
  total_vulnerabilities: 1,
  critical_paths_count: 1,
  dangerous_chains_count: 1,
  final_trust_score: 0.4,
  total_tokens: 1000,
  created_at: "2026-06-22T10:00:00Z",
  started_at: "2026-06-22T10:00:01Z",
  completed_at: "2026-06-22T10:05:00Z",
  config_json: {},
  error: null,
  phase_results: [],
  graph_state_json: {
    nodes: [
      { id: "agent_main", node_type: "agent", name: "Orchestrator" },
      { id: "cap_search", node_type: "capability", name: "Search", phase: "reconnaissance" },
      { id: "tool_email", node_type: "tool", name: "send_email", phase: "capability_mapping" },
      { id: "v_inj", node_type: "vulnerability", name: "Prompt Injection", severity: "high", phase: "vulnerability_discovery" },
    ],
    edges: [
      { source: "agent_main", target: "cap_search", edge_type: "uses_tool" },
      { source: "cap_search", target: "v_inj", edge_type: "exploits" },
      { source: "v_inj", target: "tool_email", edge_type: "can_chain_to" },
    ],
    campaign_start: "2026-06-22T10:00:01Z",
    campaign_duration_seconds: 299,
    stats: { total_nodes: 4, total_edges: 3, density: 0.25, node_types: {} },
  },
  result_json: {
    critical_paths: [["cap_search", "v_inj", "tool_email"]],
    attack_results: [
      {
        vector_id: "v_inj",
        vector_name: "Prompt Injection",
        successful: true,
        severity: "high",
        category: "injection",
        owasp_mapping: ["LLM01"],
        atlas_mapping: ["AML.T0051"],
      },
    ],
  },
}

test.describe("Knowledge graph drill-down (spec 026 US2)", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("**/api/runs/run-graph-2", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockRun) }),
    )
  })

  test("offers clustering, the chain walker, and cross-linked attack log", async ({ page }) => {
    await page.goto("/runs/run-graph-2")
    await page.waitForLoadState("networkidle")

    // Clustering control with an agent-grouping option (run has an agent node).
    const cluster = page.getByLabel("Cluster mode")
    await expect(cluster).toBeVisible()
    await expect(cluster.locator("option", { hasText: "Group: agent" })).toHaveCount(1)

    // Attack-chain walker is enabled (run has a discovered path).
    const walk = page.getByRole("button", { name: /Walk chain/i })
    await expect(walk).toBeEnabled()
    await walk.click()
    await expect(page.getByText("1/3")).toBeVisible() // step indicator

    // Cross-linked attack log: clicking a row focuses the matching node.
    const logRow = page.locator("#attack-v_inj")
    await expect(logRow).toBeVisible()
    await logRow.click()
    await expect(logRow).toHaveAttribute("aria-pressed", "true")
  })
})
