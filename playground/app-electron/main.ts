import { setupElectronAuthMain } from "@witchcraft/nuxt-auth/electron/main"
import { zAuthUserStored } from "@witchcraft/nuxt-auth/types"
import { STATIC } from "@witchcraft/nuxt-electron/electron"
import { createPrivilegedProtocolScheme, createProxiedProtocolHandler, getPaths } from "@witchcraft/nuxt-electron/electron/main"
import { useElectronLogger } from "@witchcraft/nuxt-logger/electron/main"
import { app, BrowserWindow, ipcMain, protocol, session, shell } from "electron"
import path from "node:path"

import { setupTestMultiUser } from "./setupTestMultiUser.js"

// you can get this with the magic explained in @witchcraft/nuxt-electron
const rc = STATIC.ELECTRON_RUNTIME_CONFIG as any
const protocolName = "app"

let win: BrowserWindow | undefined
let ses: Electron.Session | undefined
let activeUserId: string | undefined
const handledSessions = new WeakSet<Electron.Session>()

const logger = useElectronLogger(
	{
		...rc.logger,
		// with electron the log path is only known at runtime
		logPath: path.join(app.getPath("userData"), "log.txt")
	},
	() => win ? [win] : []
)

const paths = getPaths(protocolName, {
	publicServerUrl: process.env.OVERRIDE_PUBLIC_SERVER_URL,
	windowUrl: process.env.OVERRIDE_WINDOW_URL
})

const windowUrl = process.env.VITE_DEV_SERVER_URL || process.env.OVERRIDE_WINDOW_URL
	? paths.windowUrl
	: `${protocolName}://bundle/`

protocol.registerSchemesAsPrivileged([
	createPrivilegedProtocolScheme(protocolName)
])


// registration pattern: https://www.electronjs.org/docs/latest/tutorial/launch-app-from-url-in-another-app
// the deeplink scheme is ours to register because better-auth's own handler only writes
// the cookies into its client storage, so nothing would reach the window session
let isRegistered = false
const deeplinkScheme = rc.auth.deeplinkSchemes.electron as string

if (process.defaultApp) {
	if (process.argv.length >= 2) {
		isRegistered = app.setAsDefaultProtocolClient(deeplinkScheme, process.execPath, [path.resolve(process.argv[1]!)])
	}
} else {
	isRegistered = app.setAsDefaultProtocolClient(deeplinkScheme)
}

if (!isRegistered) {
	logger.error({ ns: "main:deeplink", scheme: deeplinkScheme })
}


// eslint-disable-next-line prefer-const -- assigned after setupTestMultiUser, which needs it in a callback
let electronAuth: ReturnType<typeof setupElectronAuthMain>["electronAuth"]

const { readActiveUser, restoreLocalUserSession, scanAndListUsers, recordExternalUser } = setupTestMultiUser({
	saveLocalUserSession: (win, authUser) => {
		return electronAuth.saveLocalUserSession(win, authUser)
	},
	setActiveUser: id => { activeUserId = id },
	reopenWindow: async () => {
		win?.close()
		await createWindow()
	}
})

/**
 * The main process side of better-auth's electron client, the preload bridges talk to it.
 *
 * Call it before `app.whenReady()`. It uses `@better-auth/electron`'s `storage()`, which
 * needs `conf` installed in the app.
 */
electronAuth = setupElectronAuthMain(rc.auth, {
	publicServerUrl: paths.publicServerUrl,
	userSchema: zAuthUserStored,
	getSession: () => ses,
	getWindow: () => win,
	getActiveUserId: () => activeUserId,
	onFinishLogin: ({ user }) => recordExternalUser(user)
}).electronAuth

/** One partition per user id, so each user gets their own cookies, cache and storage. */
function getSessionFor(id: string | undefined): Electron.Session {
	return id ? session.fromPartition(`persist:playground:${id}`) : session.defaultSession
}

/** Creates a window for the active user. If you close a window, change the active user, then reload, you can switch a user's session. */
async function createWindow(): Promise<void> {
	ses = getSessionFor(activeUserId)
	const username = activeUserId ? (await scanAndListUsers()).find(entry => entry.id === activeUserId)?.username : undefined

	if (!handledSessions.has(ses)) {
		handledSessions.add(ses)

		// The cookie lives in the window's session and this proxy is what sends it to the server, so pass the same session the window uses.
		createProxiedProtocolHandler(
			ses.protocol,
			protocolName,
			paths.nuxtPublicDir,
			{ "/api": paths.publicServerUrl },
			{ session: ses }
		)
	}

	const window = new BrowserWindow({
		// Electron derives the window class from package.json, and no switch overrides it
		// (electron#45866), so a test run marks the title instead, which a window manager
		// rule can target.
		title: `${app.getName()}${username ? ` - ${username}` : ""}${process.env.TEST === "true" ? " (test)" : ""}`,
		webPreferences: {
			contextIsolation: true,
			nodeIntegration: false,
			preload: paths.preloadPath,
			session: ses
		}
	})
	window.on("closed", () => {
		if (win === window) win = undefined
	})
	win = window

	void restoreLocalUserSession(window)
	await window.loadURL(windowUrl)
}


app.on("window-all-closed", () => undefined)

ipcMain.handle("auth.openExternal", async (_event, url: string) => {
	await shell.openExternal(url)
})

// we only support running in single instance mode
const gotTheLock = app.requestSingleInstanceLock()

if (!gotTheLock) {
	app.quit()
} else {
	/** Brings the window forward when the app is opened again. */
	function focusWindow(): void {
		if (!win) return
		if (win.isMinimized()) win.restore()
		win.focus()
	}

	app.on("second-instance", async (_event, commandLine) => {
		if (process.platform === "darwin") return
		for (const arg of commandLine) {
			if (!await electronAuth.handleUrl(arg)) continue
			focusWindow()
			break
		}
	})

	app.on("open-url", async (_event, url) => {
		if (process.platform !== "darwin") return
		if (!await electronAuth.handleUrl(url)) return
		focusWindow()
	})

	void app.whenReady().then(async () => {
		activeUserId = await readActiveUser()
		await createWindow()
	})
}
