import { _electron as electron, type ElectronApplication, expect, type Page } from "@playwright/test"
import { existsSync } from "node:fs"
import { rm } from "node:fs/promises"
import { fileURLToPath } from "node:url"

const playgroundDir = fileURLToPath(new URL("../..", import.meta.url))
/** One profile for every launch, in the repo (gitignored) so it can be inspected. */
const userDataDir = fileURLToPath(new URL("../../../.user-data-dir", import.meta.url))
/** The production build of the playground app, made with `pnpm build:electron:no-pack`. */
const mainEntry = fileURLToPath(new URL("../../.dist/electron/build/main.mjs", import.meta.url))

/** The app is an SPA, so the window opens on the root route. */
export const windowUrl = "app://bundle/"

/**
 * Launches the built playground app and waits for its window.
 *
 * Every launch shares `.user-data-dir`, which is wiped first so a session stored by an
 * earlier test never leaks into this one.
 */
export async function launchApp({ env }: { env?: Record<string, string> } = {}): Promise<{ app: ElectronApplication, page: Page, close: () => Promise<void> }> {
	if (!existsSync(mainEntry)) {
		throw new Error(`Missing ${mainEntry}, run \`pnpm build:electron:no-pack\` in playground first.`)
	}
	if (process.env.TEST_ELECTRON_DEV && !process.env.NUXT_PORT) {
		throw new Error("NUXT_PORT is not set, the test server port must be known to point the app at it.")
	}
	const serverUrl = process.env.LOCALHOST_KEY_PEM && process.env.LOCALHOST_PEM
		? `https://localhost:${process.env.NUXT_PORT}`
		: `http://localhost:${process.env.NUXT_PORT}`
	await rm(userDataDir, { recursive: true, force: true })
	// no SUID sandbox helper on nix
	const app = await electron.launch({
		// launched as an app directory so `app.getAppPath()` is the app root, which is
		// where @witchcraft/nuxt-logger resolves pino's workers from
		args: [".", "--no-sandbox", "--ignore-certificate-errors", `--user-data-dir=${userDataDir}`],
		cwd: playgroundDir,
		env: {
			...process.env,
			...env,
			DISABLE_AUTO_UPDATES: "true",
			OVERRIDE_PUBLIC_SERVER_URL: serverUrl,
			...(process.env.TEST_ELECTRON_DEV === "1" ? { VITE_DEV_SERVER_URL: serverUrl } : {})
		} as Record<string, string>
	})
	const page = await app.firstWindow()
	await page.waitForLoadState()
	const close = async () => {
		await app.close()
	}
	return { app, page, close }
}

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
 * Cancels every http request the window makes, at the session's network service, so the proxied
 * calls fail instead of being answered. Close enough to "the server is unreachable", and nothing
 * about the client is faked.
 */
export async function blockNetwork(app: ElectronApplication): Promise<void> {
	await app.evaluate(async electron => {
		const win = electron.BrowserWindow.getAllWindows()[0]
		win!.webContents.session.webRequest.onBeforeRequest({ urls: ["http://*/*"] }, (_details, callback) => callback({ cancel: true }))
	})
}

/** Lets the window's http requests through again, after `blockNetwork`. */
export async function unblockNetwork(app: ElectronApplication): Promise<void> {
	await app.evaluate(async electron => {
		const win = electron.BrowserWindow.getAllWindows()[0]
		win!.webContents.session.webRequest.onBeforeRequest(null)
	})
}

/**
 * Ends the active session on the spot: the row on the server is moved into the past, and so is the expiry note the window reads, which is what `isExpired` and the middleware go by.
 *
 * Only the session that exists when this runs dies, so a later sign-in in the same app is a real one. Both session cookies are `httpOnly`, so the jar has to hand the token over.
 */
export async function expireActiveSession(app: ElectronApplication, page: Page): Promise<void> {
	const found = (await getWindowCookies(app)).find(cookie => cookie.name.endsWith(".session_token"))
	if (!found) throw new Error("expireActiveSession: the window has no session cookie.")
	const cookie = `${found.name}=${found.value}`

	const expiresAt = Date.now() - 1000
	const baseUrl = `http://localhost:${process.env.NUXT_PORT}`
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

/** Reads the cookies of the app's window session, all of them or the ones named. */
export async function getWindowCookies(app: ElectronApplication, name?: string) {
	return app.evaluate(async (electron, cookieName) => {
		const win = electron.BrowserWindow.getAllWindows()[0]
		if (!win) return []
		return win.webContents.session.cookies.get(cookieName ? { name: cookieName } : {})
	}, name)
}
