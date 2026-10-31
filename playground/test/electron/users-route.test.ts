// screenshotting is commented out, uncomment the helper and the calls to bring it back
// import { writeFile } from "node:fs/promises"
// import type { ElectronApplication, Page } from "@playwright/test"

import { expect, test } from "./fixtures.js"
import { mockLogin, windowUrl } from "./utils.js"

// in dev mode the window lives on the server origin, which has its own storage, so stay on it
const baseUrl = process.env.TEST_ELECTRON_DEV === "1" ? `http://localhost:${process.env.NUXT_PORT}/` : windowUrl
const someoneElsesPage = `${baseUrl}users/someone`

test("signed out visitor is sent to login", async ({ page }) => {
	await page.goto(someoneElsesPage)
	// await capture(app, page, "signed-out")

	await expect(page).toHaveURL(`${baseUrl}auth/login`)
})

test("local user sees their own page, with no server value", async ({ page, getPageFromWindow }) => {
	// bundle-only: the dev server renders the page itself, so there is always a server value
	test.skip(process.env.TEST_ELECTRON_DEV === "1", "needs the app:// bundle window")
	await page.getByRole("link", { name: "Login / Register" }).click()
	await page.getByRole("button", { name: "Create Local User" }).click()
	// scoped to the picker: the login page behind it has its own Username field
	const input = page.locator(".auth-local-users--container").getByLabel("Username")
	await input.fill("localuser")
	await expect(input).toHaveValue("localuser")
	await page.getByRole("button", { name: "Create and Switch" }).click()
	const reopened = await getPageFromWindow()

	await reopened.goto(`${baseUrl}users/localuser`)
	// await capture(app, reopened, "local")

	await expect(reopened.getByText("Server user: not rendered on the server")).toBeVisible()
	await expect(reopened.getByText("Client user: localuser")).toBeVisible()
})

test("external user sees their own page, with no server value", async ({ page }) => {
	// bundle-only: the dev server renders the page itself, so there is always a server value
	test.skip(process.env.TEST_ELECTRON_DEV === "1", "needs the app:// bundle window")
	await mockLogin(page)
	const username = await page.evaluate(async () => {
		const body = await fetch("/api/auth/get-session").then(res => res.json())
		return body?.user?.username ?? null
	})

	await page.goto(`${baseUrl}users/${username}`)
	// await capture(app, page, "external")

	await expect(page.getByText("Server user: not rendered on the server")).toBeVisible()
	await expect(page.getByText(`Client user: ${username}`)).toBeVisible()
})

test("signed in user asking for somebody else's page gets a 404", async ({ page }) => {
	await mockLogin(page)

	await page.goto(someoneElsesPage)
	// await capture(app, page, "someone-else")

	await expect(page.getByText("404", { exact: true })).toBeVisible()
})

// async function capture(app: ElectronApplication, page: Page, name: string): Promise<void> {
// 	await page.waitForFunction(() => (document.querySelector("#__nuxt")?.textContent ?? "").trim() !== "")
//
// 	// capturePage returns the last composited frame, so keep asking until two frames match
// 	let previous = ""
// 	for (let i = 0; i < 20; i++) {
// 		const image = await app.evaluate(async electron => {
// 			const win = electron.BrowserWindow.getAllWindows()[0]!
// 			try {
// 				const screenshot = await win.webContents.capturePage()
// 				return screenshot.resize({ width: 1280 }).toPNG().toString("base64")
// 			} catch {
// 				// the window has not painted yet, main cannot capture it
// 				return ""
// 			}
// 		})
// 		if (image && image === previous) {
// 			await writeFile(`/tmp/users-route-${name}.png`, Buffer.from(image, "base64"))
// 			return
// 		}
// 		previous = image
// 		await new Promise(resolve => setTimeout(resolve, 200))
// 	}
// 	throw new Error("capture: the window never settled on a frame")
// }
