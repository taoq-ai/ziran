import { test, expect } from "@playwright/test"

// A small but representative multi-phase graph: phase nodes, a dangerous
// capability, a severity-bearing vulnerability, and centrality on a hub node.
const mockRun = {
  id: "run-graph-1",
  name: "Graph demo run",
  target_agent: "https://agent.acme.com",
  status: "completed",
  coverage_level: "standard",
  strategy: "balanced",
  total_vulnerabilities: 1,
  critical_paths_count: 1,
  dangerous_chains_count: 1,
  final_trust_score: 0.42,
  total_tokens: 1000,
  created_at: "2026-06-22T10:00:00Z",
  started_at: "2026-06-22T10:00:01Z",
  completed_at: "2026-06-22T10:05:00Z",
  config_json: {},
  result_json: null,
  error: null,
  phase_results: [],
  graph_state_json: {
    nodes: [
      { id: "phase_recon", node_type: "phase", name: "Reconnaissance", phase: "reconnaissance" },
      { id: "cap_search", node_type: "capability", name: "Search", phase: "reconnaissance", centrality: 1.0 },
      { id: "tool_email", node_type: "tool", name: "send_email", phase: "capability_mapping", dangerous: true },
      { id: "vuln_1", node_type: "vulnerability", name: "Prompt Injection", severity: "high", phase: "vulnerability_discovery" },
      { id: "data_db", node_type: "data_source", name: "User DB", phase: "exfiltration" },
    ],
    edges: [
      { source: "cap_search", target: "phase_recon", edge_type: "discovered_in" },
      { source: "cap_search", target: "tool_email", edge_type: "enables" },
      { source: "cap_search", target: "vuln_1", edge_type: "exploits" },
      { source: "tool_email", target: "data_db", edge_type: "accesses_data" },
    ],
    campaign_start: "2026-06-22T10:00:01Z",
    campaign_duration_seconds: 299,
    stats: { total_nodes: 5, total_edges: 4, density: 0.2, node_types: {} },
  },
}

test.describe("Knowledge graph structure (spec 026 US1)", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("**/api/runs/run-graph-1", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockRun) }),
    )
  })

  test("offers layout modes and an interactive legend filter", async ({ page }) => {
    await page.goto("/runs/run-graph-1")
    await page.waitForLoadState("networkidle")

    await expect(page.getByRole("heading", { name: /Knowledge Graph/i })).toBeVisible()

    // Layout-mode toggle (force / hierarchical / centrality).
    const force = page.getByRole("button", { name: "Force", exact: true })
    const byPhase = page.getByRole("button", { name: "By Phase", exact: true })
    await expect(force).toBeVisible()
    await expect(byPhase).toBeVisible()
    await expect(force).toHaveAttribute("aria-pressed", "true")

    // Switching layout updates the pressed state.
    await byPhase.click()
    await expect(byPhase).toHaveAttribute("aria-pressed", "true")
    await expect(force).toHaveAttribute("aria-pressed", "false")

    // Legend doubles as a filter — node types are present and toggleable.
    const vulnToggle = page.getByRole("button", { name: /vulnerability/i }).first()
    await expect(vulnToggle).toBeVisible()
    await expect(vulnToggle).toHaveAttribute("aria-pressed", "true")
    await vulnToggle.click()
    await expect(vulnToggle).toHaveAttribute("aria-pressed", "false")

    // Severity filter band is rendered for the high-severity vulnerability.
    await expect(page.getByRole("button", { name: /high/i }).first()).toBeVisible()
  })
})
