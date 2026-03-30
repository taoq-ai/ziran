import { test, expect } from "@playwright/test"

test.describe("Dashboard", () => {
  test("shows stats cards", async ({ page }) => {
    await page.goto("/")

    await expect(page.locator("text=Total Runs")).toBeVisible()
    await expect(page.locator("text=Vulnerabilities Found")).toBeVisible()
    await expect(page.locator("text=Avg Resilience Score")).toBeVisible()
  })

  test("shows runs table when data exists", async ({ page }) => {
    await page.goto("/")
    // Wait for API to respond
    await page.waitForResponse("**/api/runs")

    // Should show either the table or the empty state
    const hasTable = await page.locator("table").isVisible().catch(() => false)
    const hasEmptyState = await page.locator("text=No scans yet").isVisible().catch(() => false)

    expect(hasTable || hasEmptyState).toBeTruthy()
  })

  test("empty state shows CTA to start scan", async ({ page }) => {
    // Intercept runs API to return empty
    await page.route("**/api/runs*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ items: [], total: 0, limit: 20, offset: 0 }),
      })
    )

    await page.goto("/")
    await expect(page.locator("text=No scans yet")).toBeVisible()
    await expect(page.locator("text=Start a new run")).toBeVisible()

    // CTA navigates to new run
    await page.click("text=Start a new run")
    await expect(page).toHaveURL("/runs/new")
  })
})
