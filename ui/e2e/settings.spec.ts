import { test, expect } from "@playwright/test"

test.describe("Settings", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("**/api/configs", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([]),
      })
    )
  })

  test("shows LLM configuration section", async ({ page }) => {
    await page.goto("/settings")

    await expect(page.getByRole("heading", { name: "LLM Configuration" })).toBeVisible()
    await expect(page.getByText("Provider", { exact: true })).toBeVisible()
    await expect(page.getByText("Model", { exact: true }).first()).toBeVisible()
    await expect(page.getByText("API Key Env Variable")).toBeVisible()
    await expect(page.getByText("Temperature", { exact: true })).toBeVisible()
    await expect(page.getByText("Max Tokens", { exact: true })).toBeVisible()
  })

  test("shows scan settings section", async ({ page }) => {
    await page.goto("/settings")

    await expect(page.locator("text=Default Scan Settings")).toBeVisible()
    await expect(page.locator("text=Coverage Level")).toBeVisible()
    await expect(page.locator("text=Strategy")).toBeVisible()
    await expect(page.locator("text=Concurrency")).toBeVisible()
    await expect(page.locator("text=Attack Timeout")).toBeVisible()
    await expect(page.locator("text=Phase Timeout")).toBeVisible()
    await expect(page.locator("text=Stop on critical finding")).toBeVisible()
  })

  test("shows autonomous agent section", async ({ page }) => {
    await page.goto("/settings")

    await expect(page.getByRole("heading", { name: "Autonomous Pentesting Agent" })).toBeVisible()
    await expect(page.locator("text=Max Iterations")).toBeVisible()
  })

  test("save button persists to localStorage", async ({ page }) => {
    await page.goto("/settings")

    // Change model
    const modelInput = page.locator('input[placeholder="gpt-4o"]')
    await modelInput.fill("claude-sonnet-4-20250514")

    // Save
    await page.click("text=Save Settings")
    await expect(page.locator("text=Saved!")).toBeVisible()

    // Reload and verify persistence
    await page.reload()
    await expect(modelInput).toHaveValue("claude-sonnet-4-20250514")
  })

  test("scan presets section is collapsible", async ({ page }) => {
    await page.goto("/settings")

    // Presets section collapsed by default
    await expect(page.locator("text=Scan Presets")).toBeVisible()
    await expect(page.locator("text=No presets saved yet")).not.toBeVisible()

    // Expand
    await page.click("text=Scan Presets")
    await expect(page.locator("text=No presets saved yet")).toBeVisible()
  })
})
