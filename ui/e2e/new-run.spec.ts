import { test, expect } from "@playwright/test"

test.describe("New Run", () => {
  test("form renders with all fields", async ({ page }) => {
    await page.goto("/runs/new")

    await expect(page.locator("h2")).toContainText("New Run")
    await expect(page.locator('input[placeholder="My scan"]')).toBeVisible()
    await expect(
      page.locator(
        'input[placeholder*="https://agent.example.com"]'
      )
    ).toBeVisible()
    await expect(page.locator("text=Protocol")).toBeVisible()
    await expect(page.locator("text=Coverage")).toBeVisible()
    await expect(page.locator("text=Strategy")).toBeVisible()
    await expect(page.locator("text=Concurrency")).toBeVisible()
    await expect(page.locator("text=Start Scan")).toBeVisible()
    await expect(page.locator("text=Cancel")).toBeVisible()
  })

  test("submit button disabled without target URL", async ({ page }) => {
    await page.goto("/runs/new")
    const submitBtn = page.locator('button[type="submit"]')
    await expect(submitBtn).toBeDisabled()
  })

  test("cancel navigates back to dashboard", async ({ page }) => {
    await page.goto("/runs/new")
    await page.click("text=Cancel")
    await expect(page).toHaveURL("/")
  })

  test("preset dropdown populates form fields", async ({ page }) => {
    // Mock configs API with a preset
    await page.route("**/api/configs", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          {
            id: "preset-1",
            name: "Quick Test",
            description: "Fast scan",
            config_json: {
              coverage_level: "essential",
              strategy: "adaptive",
              concurrency: 3,
            },
            created_at: "2026-03-30T00:00:00Z",
            updated_at: "2026-03-30T00:00:00Z",
          },
        ]),
      })
    )

    await page.goto("/runs/new")

    // Preset dropdown should appear
    const presetSelect = page.locator("text=Load from preset").locator("..").locator("select")
    await expect(presetSelect).toBeVisible()

    // Select preset
    await presetSelect.selectOption("preset-1")

    // Form fields should update
    const coverageSelect = page.locator('select').nth(2) // coverage is 3rd select
    await expect(coverageSelect).toHaveValue("essential")
  })
})
