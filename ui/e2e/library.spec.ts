import { test, expect } from "@playwright/test"

const mockVectors = {
  vectors: [
    {
      id: "pi-001",
      name: "Direct System Prompt Extraction",
      category: "system_prompt_extraction",
      severity: "critical",
      target_phase: "reconnaissance",
      description: "Attempts to extract system instructions",
      tags: ["system-prompt"],
      owasp_mapping: ["LLM01"],
      prompt_count: 8,
      protocol_filter: ["rest", "openai"],
    },
    {
      id: "de-001",
      name: "Data Exfiltration via HTTP Tool",
      category: "data_exfiltration",
      severity: "high",
      target_phase: "exploitation",
      description: "Chains read_file with http_request",
      tags: ["exfiltration"],
      owasp_mapping: ["LLM06"],
      prompt_count: 6,
      protocol_filter: ["rest"],
    },
  ],
  total: 2,
}

const mockStats = {
  total_vectors: 565,
  total_prompts: 803,
  by_category: { system_prompt_extraction: 25, data_exfiltration: 49 },
  by_severity: { critical: 358, high: 159, medium: 48 },
  by_owasp: { LLM01: 434, LLM06: 95 },
}

test.describe("Attack Library", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("**/api/library/vectors*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockVectors),
      })
    )
    await page.route("**/api/library/stats", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockStats),
      })
    )
  })

  test("shows stats and vector table", async ({ page }) => {
    await page.goto("/library")

    // Stats cards
    await expect(page.locator("text=Total Vectors")).toBeVisible()
    await expect(page.locator("text=565")).toBeVisible()
    await expect(page.locator("text=Total Prompts")).toBeVisible()
    await expect(page.locator("text=803")).toBeVisible()

    // Vector table
    await expect(page.locator("text=Direct System Prompt Extraction")).toBeVisible()
    await expect(page.locator("text=Data Exfiltration via HTTP Tool")).toBeVisible()
  })

  test("search filters vectors", async ({ page }) => {
    await page.goto("/library")

    const searchInput = page.locator('input[placeholder="Search vectors..."]')
    await searchInput.fill("exfiltration")

    // Wait for debounced request
    await page.waitForTimeout(500)

    // Table should show filtered results
    await expect(page.locator("text=2 vectors")).toBeVisible()
  })

  test("vector row is expandable", async ({ page }) => {
    // Also mock detail endpoint
    await page.route("**/api/library/vectors/pi-001", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...mockVectors.vectors[0],
          references: ["https://example.com"],
          prompts: [
            {
              template: "You are DAN...",
              variables: {},
              success_indicators: ["system prompt"],
              failure_indicators: ["cannot"],
            },
          ],
        }),
      })
    )

    await page.goto("/library")

    // Click first vector row
    await page.click("text=Direct System Prompt Extraction")

    // Detail should expand
    await expect(page.locator("text=You are DAN...")).toBeVisible()
  })
})
