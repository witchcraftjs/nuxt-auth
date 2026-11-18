import { expect, type Page } from "@playwright/test"
import type { Cookie } from "electron"

import { localhostUrl } from "../../localhostUrl.js"

/** The app is an SPA, so the window opens on the root route. */
export const windowUrl = "app://bundle/"

/**
 * Signs in the way a person does: the login page, the dev bypass checkbox, then a provider button.
 * Main answers the provider request with the mock, and the window ends up signed in as a user that
 * has no username yet, so the app sends it to register.
 */
export async function mockLogin(page: Page): Promise<void> {
	await page.goto(`${windowUrl}auth/login`)
	await page.getByRole("checkbox", { name: "Dev Bypass/Mock Auth" }).click()
	await page.getByRole("checkbox", { name: "Bypass Registration for New Users" }).click()
	await page.getByRole("button", { name: /github/i }).click()
	await page.waitForURL(url => new URL(url).pathname !== "/auth/login")

	await expect.poll(async () => page.evaluate(async () => {
		const body = await fetch("/api/auth/get-session").then(res => res.json())
		return body?.user?.id ?? null
	}).catch((error: Error) => {
		// the renderer and main both load the callback page while we ask, so the document can be gone
		if (error.message.includes("Execution context was destroyed")) return null
		throw error
	})).not.toBeNull()
}

/**
 * Ends the active session on the spot: the row on the server is moved into the past, and so is the expiry note the window reads, which is what `isExpired` and the middleware go by.
 *
 * Only the session that exists when this runs dies, so a later sign-in in the same app is a real one. Both session cookies are `httpOnly`, so the jar has to hand the token over.
 */
export async function expireActiveSession(page: Page, getWindowCookies: (page: Page, name?: string) => Promise<Cookie[]>): Promise<void> {
	const found = (await getWindowCookies(page)).find(cookie => cookie.name.endsWith(".session_token"))
	if (!found) throw new Error("expireActiveSession: the window has no session cookie.")
	const cookie = `${found.name}=${found.value}`

	const expiresAt = Date.now() - 1000
	const baseUrl = localhostUrl()
	const response = await fetch(`${baseUrl}/api/auth/dev/mock/session`, {
		method: "POST",
		headers: { "content-type": "application/json", cookie, origin: baseUrl },
		body: JSON.stringify({ expiresAt })
	})

	if (!response.ok) {
		throw new Error(`expireActiveSession: moving the session expiry back failed with ${response.status} ${await response.text()}`)
	}

	await page.evaluate(at => localStorage.setItem("auth:external:expiresAt", String(at)), expiresAt)
}
