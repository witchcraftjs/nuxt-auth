import { expect, test } from "./fixtures.js"
import { blockNetwork, mockLogin, windowUrl } from "./utils.js"

import type { PlaygroundWindow } from "../../preload-types.js"

test("app opens its window", async ({ app, page }) => {
	const url = page.url()
	const name = await app.evaluate(async ({ app }) => app.getName())

	const expectedPrefix = process.env.TEST_ELECTRON_DEV === "1" ? `http://localhost:${process.env.NUXT_PORT}` : windowUrl
	expect(url.startsWith(expectedPrefix)).toBe(true)
	expect(name).toBeTruthy()
})

test("window exposes log, user, authenticate, session bridges", async ({ page }) => {
	const bridges = await page.evaluate(() => {
		const appWindow = window as unknown as PlaygroundWindow
		return {
			log: typeof appWindow.electron.api.log,
			switchUserAndSoftReload: typeof appWindow.electron.api.users.switchUserAndSoftReload,
			authenticate: typeof appWindow.authenticate,
			exchangeSession: typeof appWindow.electron.api.auth.exchangeSession
		}
	})

	expect(bridges.log).toBe("function")
	expect(bridges.switchUserAndSoftReload).toBe("function")
	expect(bridges.authenticate).toBe("function")
	expect(bridges.exchangeSession).toBe("function")
})

test("app starts with no user signed in", async ({ page }) => {
	const user = await page.evaluate(async () => (globalThis as any).getUser())

	expect(user).toBeNull()
})

test("signed out visitor is sent from the app bundle to login, not the server", async ({ page }) => {
	// bundle-only: in dev mode the window already lives on the server origin
	test.skip(process.env.TEST_ELECTRON_DEV === "1", "needs the app:// bundle window")
	await page.goto(`${windowUrl}users/someone`)
	// the app is an SPA, so the window stays empty until the router has run
	await page.waitForFunction(() => (document.querySelector("#__nuxt")?.textContent ?? "").trim() !== "")
	await page.waitForURL(`${windowUrl}auth/login`)

	const state = await page.evaluate(() => ({ origin: window.location.origin, href: window.location.href }))
	// playwright cannot screenshot the app scheme, and a window that has not painted yet
	// makes main's capture fail with UnknownVizError
	// await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))

	// const screenshot = await app.evaluate(async electron => {
	// 	const image = await electron.BrowserWindow.getAllWindows()[0]!.webContents.capturePage()
	// 	return image.resize({ width: 1280 }).toPNG().toString("base64")
	// })
	// await test.info().attach("users-route.png", { body: Buffer.from(screenshot, "base64"), contentType: "image/png" })

	// node treats app:// as an opaque origin, only the renderer reports scheme and host
	expect(state.origin).toBe(`${new URL(windowUrl).protocol}//${new URL(windowUrl).host}`)
	expect(state.href).toBe(`${windowUrl}auth/login`)
})

test("window reaches server through proxy", async ({ page }) => {
	const session = await page.evaluate(async () => {
		const res = await fetch("/api/auth/get-session")
		return { status: res.status, body: await res.text() }
	})

	expect(session.status).toBe(200)
	expect(session.body).toBe("null")
})

test("main holds one window with a session", async ({ app }) => {
	const state = await app.evaluate(async electron => {
		const windows = electron.BrowserWindow.getAllWindows()
		return {
			windows: windows.length,
			hasSession: !!windows[0]?.webContents.session
		}
	})

	expect(state).toEqual({ windows: 1, hasSession: true })
})

test("window can call server routes", async ({ page }) => {
	const post = await page.evaluate(async () => {
		const res = await fetch("/api/auth/is-username-available", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ username: "apppostusername" })
		})
		return { status: res.status, body: await res.text() }
	})
	const route = await page.evaluate(async () => {
		const res = await fetch("/api/auth/username/valid?username=apppostusername2")
		return { status: res.status, body: await res.text() }
	})

	expect(post).toEqual({ status: 200, body: JSON.stringify({ available: true }) })
	expect(route).toEqual({ status: 200, body: "true" })
})

/**
 * A call that never reaches the server surfaces as the raw fetch error, shown by the page's
 * error box. `setOffline` only affects the window's own network stack, so the session's network
 * service cancels the request instead, and nothing about the client is faked.
 */
test("call (network blocked) => fails with a fetch error", async ({ app, page }) => {
	await mockLogin(page)
	// cancelling in the session's network service fails the proxied call without faking the
	// client, which is as close to "the server is unreachable" as a test can get
	await blockNetwork(app)

	await page.getByRole("button", { name: "Update name" }).click()

	await expect(page.getByText(/Failed to fetch/)).toBeVisible()
})
