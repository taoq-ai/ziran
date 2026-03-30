import { test, expect } from "@playwright/test"

test.describe("Navigation", () => {
  test("sidebar links navigate to all pages", async ({ page }) => {
    await page.goto("/")

    // Dashboard loads
    await expect(page.locator("h2")).toContainText("Dashboard")

    // Navigate to New Run
    await page.click('a[href="/runs/new"]')
    await expect(page.locator("h2")).toContainText("New Run")

    // Navigate to Findings (lazy-loaded)
    await page.click('a[href="/findings"]')
    await page.waitForLoadState("networkidle")
    await expect(page.getByRole("heading", { name: /Findings/i })).toBeVisible()

    // Navigate to Compliance (lazy-loaded)
    await page.click('a[href="/compliance"]')
    await page.waitForLoadState("networkidle")
    await expect(page.getByRole("heading", { name: /Compliance/i })).toBeVisible()

    // Navigate to Library
    await page.click('a[href="/library"]')
    await expect(page.locator("h2")).toContainText("Attack Library")

    // Navigate to Settings
    await page.click('a[href="/settings"]')
    await expect(page.locator("h2")).toContainText("Settings")
  })

  test("404 page renders for unknown routes", async ({ page }) => {
    await page.goto("/nonexistent-page")
    await expect(page.locator("text=404")).toBeVisible()
    await expect(page.locator("text=Page not found")).toBeVisible()

    // Back to Dashboard link works
    await page.click("text=Back to Dashboard")
    await expect(page.locator("h2")).toContainText("Dashboard")
  })

  test("sidebar shows ZIRAN branding", async ({ page }) => {
    await page.goto("/")
    await expect(page.locator("h1")).toContainText("ZIRAN")
    await expect(page.locator("text=AI Agent Security")).toBeVisible()
  })
})
