import { test, expect } from "@playwright/test"

const mockFindings = {
  items: [
    {
      id: "f1",
      run_id: "run-1",
      vector_name: "System Prompt Extraction",
      category: "system_prompt_extraction",
      severity: "critical",
      owasp_category: "LLM01",
      target_agent: "https://agent.acme.com",
      status: "open",
      title: "System prompt fully extracted",
      created_at: "2026-03-28T10:35:00Z",
    },
    {
      id: "f2",
      run_id: "run-1",
      vector_name: "Data Exfiltration",
      category: "data_exfiltration",
      severity: "high",
      owasp_category: "LLM06",
      target_agent: "https://agent.acme.com",
      status: "fixed",
      title: "Sensitive data exfiltrated via tool chain",
      created_at: "2026-03-28T10:36:00Z",
    },
  ],
  total: 2,
  limit: 25,
  offset: 0,
}

const mockStats = {
  total: 2,
  by_severity: { critical: 1, high: 1 },
  by_status: { open: 1, fixed: 1 },
  by_category: { system_prompt_extraction: 1, data_exfiltration: 1 },
  by_owasp: { LLM01: 1, LLM06: 1 },
}

test.describe("Findings", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("**/api/findings?*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockFindings),
      })
    )
    await page.route("**/api/findings/stats*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockStats),
      })
    )
  })

  test("shows findings table with data", async ({ page }) => {
    await page.goto("/findings")
    await page.waitForLoadState("networkidle")

    // Title (Findings page uses an icon + text in h2)
    await expect(page.getByRole("heading", { name: /Findings/i })).toBeVisible()

    // Table rows
    await expect(page.locator("text=System prompt fully extracted")).toBeVisible()
    await expect(page.locator("text=Sensitive data exfiltrated via tool chain")).toBeVisible()
  })

  test("export buttons are visible", async ({ page }) => {
    await page.goto("/findings")

    await expect(page.locator("text=CSV")).toBeVisible()
    await expect(page.locator("text=JSON")).toBeVisible()
  })

  test("filter dropdowns are present", async ({ page }) => {
    await page.goto("/findings")
    await page.waitForLoadState("networkidle")

    // Select dropdowns contain the filter options
    await expect(page.locator("select").nth(0)).toBeVisible()
    await expect(page.locator("select").nth(1)).toBeVisible()
    await expect(page.locator("select").nth(2)).toBeVisible()
  })
})
