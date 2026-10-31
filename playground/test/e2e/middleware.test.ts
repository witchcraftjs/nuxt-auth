import { expect, test } from "./fixtures.js"

import { createLocalUser, mockLogin, randomUsername, waitForHydration, waitUntilAtPath } from "../utils.js"

test("signed out: public pages stay, gated pages send the visitor to log in", async ({ page }) => {
	await page.goto("/")
	await expect(page.getByText("Home", { exact: true }).first()).toBeVisible()
	await waitForHydration(page)

	expect(new URL(page.url()).pathname).toBe("/")

	await page.goto("/unauthed")
	await expect(page.getByText("Unauthenticated Only", { exact: true }).first()).toBeVisible()
	await waitForHydration(page)

	expect(new URL(page.url()).pathname).toBe("/unauthed")

	await page.goto("/auth/login")
	await expect(page.getByRole("button", { name: "Create Local User" })).toBeVisible()
	await waitForHydration(page)

	expect(new URL(page.url()).pathname).toBe("/auth/login")

	await page.goto("/authed")
	await waitUntilAtPath(page, "/auth/login")

	await page.goto("/auth/register")
	await waitUntilAtPath(page, "/")
})

test("signed in: the authed page stays, the auth pages send the user away", async ({ page }) => {
	await page.goto("/auth/login")
	await createLocalUser(page, randomUsername())
	await waitUntilAtPath(page, "/authed")

	await page.goto("/authed")
	await expect(page.getByRole("button", { name: "Change password" })).toBeVisible()
	await waitForHydration(page)

	expect(new URL(page.url()).pathname).toBe("/authed")

	await page.goto("/")
	await expect(page.getByText("Home", { exact: true }).first()).toBeVisible()
	await waitForHydration(page)

	expect(new URL(page.url()).pathname).toBe("/")

	await page.goto("/unauthed")
	await waitUntilAtPath(page, "/authed")

	await page.goto("/auth/login")
	await waitUntilAtPath(page, "/authed")

	await page.goto("/auth/register")
	await waitUntilAtPath(page, "/")
})

test("signed in but not registered: gated pages keep sending the user to register", async ({ page }) => {
	await mockLogin(page)

	await page.goto("/")
	await expect(page.getByText("Home", { exact: true }).first()).toBeVisible()
	await waitForHydration(page)

	expect(new URL(page.url()).pathname).toBe("/")

	await page.goto("/auth/register")
	await expect(page.getByRole("button", { name: "Register", exact: true })).toBeVisible()
	await waitForHydration(page)

	expect(new URL(page.url()).pathname).toBe("/auth/register")

	await page.goto("/unauthed")
	await waitUntilAtPath(page, "/auth/register")

	await page.goto("/authed")
	await waitUntilAtPath(page, "/auth/register")

	await page.goto("/auth/login")
	await waitUntilAtPath(page, "/auth/register")
})
