import { expect, test } from "./fixtures.js"

import { createLocalUser, logoutAndWaitForReload, randomUsername, readAuthStorage, readStoredUser, selectLocalUser, trackSessionRequests, waitUntilAtPath } from "../utils.js"

const USERNAME = randomUsername()

test("login page => create local user => signs out => signs in from picker => deleted", async ({ page }) => {
	await page.goto("/auth/login")
	await expect(page.getByRole("button", { name: "Create Local User" })).toBeVisible()

	const sessionRequests = trackSessionRequests(page)

	await createLocalUser(page, USERNAME)
	await waitUntilAtPath(page, "/authed")

	expect((await readStoredUser(page)).type).toBe("local")
	expect(sessionRequests).toHaveLength(0)

	// a local user has no page on the server, so their link stays in the app
	await expect(page.getByRole("link", { name: USERNAME })).toHaveAttribute("href", `/users/${USERNAME}`)

	// their calls are served from the stored copy or rejected, never sent
	await page.getByRole("link", { name: "Authed Only", exact: true }).click()
	await page.getByRole("button", { name: "Change password" }).click()

	await expect(page.getByText(/not available for a local-only user/)).toBeVisible()
	expect(sessionRequests).toHaveLength(0)

	await logoutAndWaitForReload(page)

	expect((await readAuthStorage(page)).user).toBeNull()

	await page.goto("/auth/login")
	await selectLocalUser(page, USERNAME)
	await page.getByRole("button", { name: "Sign In with Selected Local User" }).click()
	await waitUntilAtPath(page, "/authed")

	expect((await readStoredUser(page)).type).toBe("local")

	await page.goto("/auth/login")

	await waitUntilAtPath(page, "/authed")

	// removing a stored user needs a signed out window
	await logoutAndWaitForReload(page)
	await page.goto("/auth/login")
	await selectLocalUser(page, USERNAME)
	await page.getByRole("button", { name: "Remove Selected Local User" }).click()
	await page.getByRole("button", { name: "Remove", exact: true }).click()

	await expect.poll(async () => (await readAuthStorage(page)).localOnlyUsers.length).toBe(0)
	await expect.poll(async () => (await readAuthStorage(page)).user).toBeNull()
})
