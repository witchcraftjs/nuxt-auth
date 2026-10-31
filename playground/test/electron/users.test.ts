import { readFile } from "node:fs/promises"
import { fileURLToPath } from "node:url"

import { expect, type Page, test } from "./fixtures.js"
import { getWindowCookies, mockLogin } from "./utils.js"

import { logoutAndWaitForReload, readStoredUser, selectLocalUser } from "../utils.js"

const publicServerUrl = `http://localhost:${process.env.NUXT_PORT}`
const USERNAME = "localuser"

/** Switches user by id and returns the recreated window. */
async function switchTo(page: Page, id: string, getPageFromWindow: () => Promise<Page>): Promise<Page> {
	void page.evaluate(userId => (globalThis as any).electron.api.users.switchUserAndSoftReload(userId), id).catch((error: unknown) => {
		// the reply can never arrive: main closes this window before it can answer
		// eslint-disable-next-line no-console
		console.warn(`[users.test] switchUserAndSoftReload reply lost: ${String(error)}`)
	})
	return getPageFromWindow()
}

/** Creates a user by id and returns the reopened window. Create also switches. */
async function createUser(page: Page, id: string, username: string, getPageFromWindow: () => Promise<Page>): Promise<Page> {
	void page.evaluate(async ({ userId, name }) => (globalThis as any).electron.api.users.create({ id: userId, username: name }), { userId: id, name: username }).catch((error: unknown) => {
		// the reply can never arrive: main closes this window before it can answer
		// eslint-disable-next-line no-console
		console.warn(`[users.test] users.create reply lost: ${String(error)}`)
	})
	return getPageFromWindow()
}

/** Creates a local user from the picker, which reopens the window. */
async function createLocalUser(page: Page, username: string, getPageFromWindow: () => Promise<Page>): Promise<Page> {
	await page.getByRole("button", { name: "Create Local User" }).click()
	// scoped to the picker: the login page behind it has its own Username field
	const input = page.locator(".auth-local-users--container").getByLabel("Username")
	await input.fill(username)
	await expect(input).toHaveValue(username)

	// main reopens the window, which destroys this one, so the click may never settle
	await page.getByRole("button", { name: "Create and Switch" }).click()
	return getPageFromWindow()
}

test("user switch keeps cookies apart", async ({ app, page, getPageFromWindow }) => {
	const aliceId = crypto.randomUUID()
	const bobId = crypto.randomUUID()

	const alice = await createUser(page, aliceId, "alice", getPageFromWindow)
	await app.evaluate(async (electron, url) => {
		const win = electron.BrowserWindow.getAllWindows()[0]
		await win!.webContents.session.cookies.set({ url, name: "user", value: "alice" })
	}, publicServerUrl)

	const aliceCookies = (await getWindowCookies(app, "user")).map(cookie => cookie.value)
	const bob = await createUser(alice, bobId, "bob", getPageFromWindow)
	const bobCookies = (await getWindowCookies(app, "user")).map(cookie => cookie.value)

	await switchTo(bob, aliceId, getPageFromWindow)

	const aliceAgain = (await getWindowCookies(app, "user")).map(cookie => cookie.value)

	expect(aliceCookies).toEqual(["alice"])
	expect(bobCookies).toEqual([])
	expect(aliceAgain).toEqual(["alice"])
})

/**
 * Electron local users are the app's, not the module's, so the playground keeps its own
 * registry and writes the user into the window after it loads.
 */
test("local user made in app => signs out => signs in from picker", async ({ page, getPageFromWindow }) => {
	await page.getByRole("link", { name: "Login / Register" }).click()
	const created = await createLocalUser(page, USERNAME, getPageFromWindow)

	// the window is written after it loads, so it may render signed out first
	await expect.poll(async () => (await readStoredUser(created))?.type).toBe("local")

	// a navigation is what makes the middleware pick the stored user up
	await created.getByRole("link", { name: "Authed Only", exact: true }).click()

	await logoutAndWaitForReload(created)

	expect(await readStoredUser(created)).toBeNull()

	await created.getByRole("link", { name: "Login / Register" }).click()
	await selectLocalUser(created, USERNAME)

	// the switch reopens the window, so the click may never settle
	await created.getByRole("button", { name: "Sign In with Selected Local User" }).click()
	const signedIn = await getPageFromWindow()

	await expect.poll(async () => (await readStoredUser(signedIn))?.type).toBe("local")

	const stored = await readStoredUser(signedIn)

	expect(stored.username).toBe(USERNAME)
	expect(stored.type).toBe("local")
})

/**
 * The registry is keyed by id and only carries the username as a label, so renaming a user keeps
 * the entry and changes only what it is called, in the list and in the directory on disk.
 */
test("external user => username rename => registry label and data dir follow by id", async ({ page }) => {
	await mockLogin(page)

	const before = await page.evaluate(() => (globalThis as any).electron.api.users.list())

	expect(before).toEqual([expect.objectContaining({ isLocal: false, username: expect.any(String) })])

	const username = "renameduser"
	// the call the plugin makes once a username update lands. It only reopens the window when the
	// updated user is the persisted active one, which a login does not make them
	await page.evaluate(
		({ id, name }: { id: string, name: string }) => (globalThis as any).electron.api.users.update({ id, patch: { username: name } }),
		{ id: before[0].id, name: username }
	)

	const after = await page.evaluate(() => (globalThis as any).electron.api.users.list())

	expect(after).toEqual([expect.objectContaining({ id: before[0].id, username })])

	const label = await readFile(fileURLToPath(new URL(`../../../.user-data-dir/users/${before[0].directory}/username`, import.meta.url)), "utf8")
	expect(label).toBe(username)
})
