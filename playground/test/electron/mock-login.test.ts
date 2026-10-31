import { expect, type Locator, type Page, test } from "./fixtures.js"
import { blockNetwork, expireActiveSession, getWindowCookies, mockLogin, unblockNetwork } from "./utils.js"

import { readAuthStorage, readStoredUser } from "../utils.js"

/** The result cell of the `/authed` table row whose first cell starts with `label`. */
function authedTableResult(page: Page, label: string): Locator {
	return page.getByRole("row", { name: new RegExp(`^${label}`) }).getByRole("cell").nth(1)
}

test("mock sign-in => code redeemed => no token in address bar", async ({ page }) => {
	await mockLogin(page)

	await expect(page).not.toHaveURL(/access_token=/)
})

test("sign-in (mocked) => user marked external, expiry matches cookie", async ({ app, page }) => {
	await mockLogin(page)

	const stored = await readStoredUser(page)
	const { externalExpiresAt } = await readAuthStorage(page)
	const cookieExpiry = (await getWindowCookies(app)).find(cookie => cookie.name.endsWith(".session_token"))?.expirationDate

	expect(stored.type).toBe("external")
	// the key holds ms, the cookie whole seconds, so they are compared at that resolution
	expect(Math.floor(Number(externalExpiresAt) / 1000)).toBe(cookieExpiry)
})

test("session (expired) keeps user => warns on page change => checks disagree => re-auth goes to login", async ({ app, page }) => {
	await mockLogin(page)
	await expireActiveSession(app, page)

	// a real link to a different page, so the middleware runs. The login lands on /authed, so
	// clicking that route again would be a no-op. A reload would work too but checks less.
	await page.getByRole("link", { name: "Home", exact: true }).click()

	await expect(page.getByTitle("You need to re-authenticate to use some parts of the app.")).toBeVisible()

	await page.getByRole("link", { name: "Authed Only", exact: true }).click()

	expect((await readStoredUser(page)).type).toBe("external")
	await expect(authedTableResult(page, "Session")).toHaveText("expired")

	await page.getByRole("button", { name: "Check expiry" }).click()

	await expect(authedTableResult(page, "Check expiry")).toHaveText("expired")

	await page.getByRole("button", { name: "Check server" }).click()

	await expect(authedTableResult(page, "Check server")).toHaveText("no session")

	// the login page admits a kept user whose session is gone, otherwise this bounces back
	await page.getByRole("button", { name: "Request re-auth" }).click()

	await expect(page).toHaveURL(/\/auth\/login$/)

	await page.getByRole("checkbox", { name: "Dev Bypass/Mock Auth" }).click()
	await page.getByRole("checkbox", { name: "Bypass Registration for New Users" }).click()
	await page.getByRole("button", { name: /github/i }).click()
	await page.waitForURL(/\/authed$/)

	await page.getByRole("link", { name: "Authed Only", exact: true }).click()
	await page.getByRole("button", { name: "Check server" }).click()

	await expect(authedTableResult(page, "Check server")).toHaveText("signed in")
})

test("session (alive) + network blocked => check server fails => the app still navigates", async ({ app, page }) => {
	await mockLogin(page)
	await blockNetwork(app)

	await page.getByRole("button", { name: "Check server" }).click()

	await expect(authedTableResult(page, "Check server")).toHaveText(/Failed to fetch/)
	await expect(page).toHaveURL(/\/authed$/)

	await page.getByRole("link", { name: "Home", exact: true }).click()

	await expect(page).toHaveURL(/app:\/\/bundle\/$/)

	await page.getByRole("link", { name: "Authed Only", exact: true }).click()

	await expect(page).toHaveURL(/\/authed$/)

	await unblockNetwork(app)
	await page.getByRole("button", { name: "Check server" }).click()

	await expect(authedTableResult(page, "Check server")).toHaveText("signed in")
})
