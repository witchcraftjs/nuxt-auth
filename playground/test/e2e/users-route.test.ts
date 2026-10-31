import { expect, test } from "./fixtures.js"

import { createLocalUser, mockLogin, randomUsername, registerThroughForm, waitUntilAtPath } from "../utils.js"

const someoneElsesPage = "/users/someone"

test("signed out visitor is sent to login", async ({ page }) => {
	await page.goto(someoneElsesPage)
	await waitUntilAtPath(page, "/auth/login")
})

test("local user: the server sees nobody, the client sees them", async ({ page }) => {
	const username = randomUsername()
	await page.goto("/auth/login")
	await createLocalUser(page, username)
	await waitUntilAtPath(page, "/authed")

	const response = await page.goto(`/users/${username}`)

	// there is no session, so the server renders the page with nobody and the client fills the rest in
	expect(response?.status()).toBe(200)
	await expect(page.getByText("Server user: none")).toBeVisible()
	await expect(page.getByText(`Client user: ${username}`)).toBeVisible()
})

test("external user: the server and the client both see them", async ({ page }) => {
	await mockLogin(page)
	const username = await registerThroughForm(page)

	const response = await page.goto(`/users/${username}`)

	expect(response?.status()).toBe(200)
	await expect(page.getByText(`Server user: ${username}`)).toBeVisible()
	await expect(page.getByText(`Client user: ${username}`)).toBeVisible()
})

test("local user asking for somebody else's page: the server cannot tell, the client refuses it", async ({ page }) => {
	const username = randomUsername()
	await page.goto("/auth/login")
	await createLocalUser(page, username)
	await waitUntilAtPath(page, "/authed")

	// a local user only exists on the client, so the server renders the page and the client throws the 404
	const response = await page.goto(someoneElsesPage)

	expect(response?.status()).toBe(200)
	await expect(page.getByText("404", { exact: true })).toBeVisible()
})

test("signed in user asking for somebody else's page gets a 404", async ({ page }) => {
	await mockLogin(page)
	await registerThroughForm(page)

	const response = await page.goto(someoneElsesPage)

	expect(response?.status()).toBe(404)
	await expect(page.getByText("404", { exact: true })).toBeVisible()
})
