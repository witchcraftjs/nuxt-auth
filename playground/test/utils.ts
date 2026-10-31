import { expect, type Page } from "@playwright/test"

import { externalExpiryStorageKey, localOnlyUsersStorageKey, userStorageKey } from "#witchcraft-nuxt-auth/types"

/**
 * A username no other test in the same run will take, so tests never fight the username
 * availability check or a leftover user in the database.
 */
export function randomUsername(): string {
	return `testuser_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
}

/**
 * Registers the signed in user through the app's own form, which is the only way a test
 * should register them. Leaves the window on the post login route and returns the username
 * it used.
 */
export async function registerThroughForm(page: Page, username: string = randomUsername()): Promise<string> {
	const input = page.getByLabel("Username")
	for (let i = 0; i < 3 && await input.inputValue() !== username; i++) {
		await input.fill(username)
	}
	await expect(input).toHaveValue(username)

	const submit = page.getByRole("button", { name: "Register", exact: true })
	await expect(submit).toBeEnabled()
	await submit.click()

	// a rejected submit leaves the window on the form, so report what the form said instead of
	// only the url
	const landed = await page.waitForURL(/\/authed$/).then(() => true).catch(() => false)
	if (!landed) {
		const form = await page.evaluate(() => document.body.textContent?.replace(/\s+/g, " ").trim() ?? "")
		throw new Error(`registerThroughForm: did not land on /authed. url: ${page.url()} form: ${form.slice(0, 500)}`)
	}
	return username
}

export async function createLocalUser(page: Page, username: string): Promise<void> {
	await page.getByRole("button", { name: "Create Local User" }).click()
	// scoped to the picker: the login page behind it has its own Username field
	await page.locator(".auth-local-users--container").getByLabel("Username").fill(username)
	await page.getByRole("button", { name: "Create and Switch" }).click()
}

/** Signs in the way a person does: login page, dev bypass, a provider, then the mock page. */
export async function mockLogin(page: Page): Promise<void> {
	await page.goto("/auth/login")
	await page.getByRole("checkbox", { name: "Dev Bypass/Mock Auth" }).click()
	await page.getByRole("button", { name: /github/i }).click()
	await expect(page).toHaveURL(/\/auth\/mock\?provider=github$/)

	await page.getByRole("textbox").fill(randomUsername())
	await page.getByRole("button", { name: "Submit" }).click()
	await expect(page).toHaveURL("/auth/register")
}

export function trackSessionRequests(page: Page): string[] {
	const urls: string[] = []
	page.on("request", request => {
		if (request.url().includes("/api/auth/get-session")) urls.push(request.url())
	})
	return urls
}

export async function readAuthStorage(page: Page): Promise<{ user: any, localOnlyUsers: any[], externalExpiresAt: number | null }> {
	return page.evaluate(({ userKey, localUsersKey, expiryKey }) => ({
		user: JSON.parse(localStorage.getItem(userKey) ?? "null"),
		localOnlyUsers: JSON.parse(localStorage.getItem(localUsersKey) ?? "[]"),
		externalExpiresAt: localStorage.getItem(expiryKey) === null ? null : Number(localStorage.getItem(expiryKey))
	}), { userKey: userStorageKey, localUsersKey: localOnlyUsersStorageKey, expiryKey: externalExpiryStorageKey })
}

export async function selectLocalUser(page: Page, username: string): Promise<void> {
	await page.locator(".combobox--input").click()
	await page.locator(".combobox--suggestion", { hasText: username }).click()
}

export async function readStoredUser(page: Page): Promise<any> {
	return page.evaluate(key => JSON.parse(localStorage.getItem(key) ?? "null"), userStorageKey)
}

export async function waitForHydration(page: Page): Promise<void> {
	await page.waitForFunction(() => "__vue_app__" in (document.querySelector("#__nuxt") ?? {}))
}

export async function waitUntilAtPath(page: Page, path: string): Promise<void> {
	await page.waitForURL(url => new URL(url).pathname === path)
}

export async function logoutAndWaitForReload(page: Page): Promise<void> {
	await page.getByRole("button", { name: "Logout" }).click()
	await page.waitForURL(url => new URL(url).pathname === "/")
	await page.waitForLoadState()
}
