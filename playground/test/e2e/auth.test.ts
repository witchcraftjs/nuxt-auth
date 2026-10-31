import type { Page } from "@playwright/test"

import { expect, test } from "./fixtures.js"

import { mockLogin, randomUsername, registerThroughForm } from "../utils.js"

const getSession = (page: Page) => page.request.get("/api/auth/get-session").then(res => res.json())

test("sign-in (mocked, no username) => register page => auto-generated name on user", async ({ page }) => {
	await mockLogin(page)

	const name = await registerThroughForm(page)
	const session = await getSession(page)

	expect(session.user.username).toBe(name)
	expect(session.user.isRegistered).toBe(true)

	await page.reload()
	const reloaded = await getSession(page)

	expect(reloaded.user.username).toBe(name)
})

test("mock submit (offline) => fails => the app still navigates", async ({ page }) => {
	await page.goto("/auth/login")
	await expect(page.getByRole("checkbox", { name: "Dev Bypass/Mock Auth" })).toBeVisible()

	await page.getByRole("checkbox", { name: "Dev Bypass/Mock Auth" }).click()
	await page.getByRole("button", { name: /github/i }).click()

	await expect(page).toHaveURL(/\/auth\/mock\?provider=github$/)

	await page.context().setOffline(true)
	await page.getByRole("textbox").fill(randomUsername())
	await page.getByRole("button", { name: "Submit" }).click()

	await expect(page).toHaveURL(/\/auth\/mock\?provider=github$/)

	await page.getByRole("link", { name: "Home", exact: true }).click()

	await expect(page).toHaveURL("/")
})
