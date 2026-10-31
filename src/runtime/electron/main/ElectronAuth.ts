import type { StandardSchemaV1 } from "@standard-schema/spec"
import type { BaseLogger } from "@witchcraft/nuxt-logger/types"
import type { BrowserWindow, Cookie, CookiesSetDetails, Session } from "electron"

import type { ModulePublicRuntimeConfig } from "../../../module.js"
import { externalExpiryStorageKey, type SessionCookieOptions, userStorageKey } from "../../types.js"


/**
 * Main-process auth helper for Electron apps.
 *
 * Replaces hand-rolled scheme regexes and cookie writing. The token exchange itself runs through better-auth (`window.authenticate` in the callback page calls main, main calls `authenticate`).
 *
 * This class owns intake and persistence around it:
 * - matching scheme urls and loading the callback page with the token
 * - mirroring the session cookie into the window session
 * - writing the user and the session expiry into the window's `localStorage`
 * - keeping the stored expiry in step when the server rolls the session
 * - local-user session injection
 */
export class ElectronAuth {
	private scheme: string
	private callbackPath: string
	private publicServerUrl: string
	private getSession: () => Session | undefined
	private getWindow: () => BrowserWindow | undefined | null
	private getActiveUserId: () => string | undefined
	private sessionCookieOpts: Pick<SessionCookieOptions, "path" | "sameSite">
	private sessionExpiresAt: number
	private cookiePrefix: string
	private userIdCookieName: string
	private useSecureCookies: boolean
	private logger: BaseLogger | undefined
	private userSchema: StandardSchemaV1<unknown, { id: string }>
	private onFinishLogin: ((info: { win: BrowserWindow, user: { id: string, username: string } }) => void | Promise<void>) | undefined
	/** Sessions whose cookie changes are already watched, so a window switch does not watch twice. */
	private watchedSessions = new WeakSet<Session>()

	constructor({
		scheme,
		userSchema,
		callbackPath,
		publicServerUrl,
		getSession,
		getWindow,
		getActiveUserId,
		sessionCookieOpts,
		sessionExpiresAt,
		cookiePrefix = "better-auth",
		userIdCookieName = "userId",
		logger,
		onFinishLogin
	}: {
		/** Custom protocol scheme, from `rc.auth.deeplinkSchemes.electron`. No trailing colon. */
		scheme: string
		/**
		 * Parses the user before it is written to the window, e.g. `zAuthUserStored`.
		 * Build it from the db table so there is one source of truth for the user shape.
		 */
		userSchema: StandardSchemaV1<unknown, { id: string }>
		/** Deeplink path the code page bounces to, from `rc.auth.authRoutes.deeplink`. */
		callbackPath: string
		/**
		 * The better-auth server the app proxies to, e.g. `getPaths().publicServerUrl` so we know what site to store the cookies securely on.
		 */
		publicServerUrl: string
		/** Returns the session the window uses, e.g. `() => ses`, undefined until the window is created. Its cookies are what the proxy sends. */
		getSession: () => Session | undefined
		/** Returns the window auth urls load into, e.g. `() => win`, null when none exists yet. */
		getWindow: () => BrowserWindow | undefined | null
		/** Returns the id of the user the app treats as active, e.g. `() => activeUserId`. */
		getActiveUserId: () => string | undefined
		/** From runtime config, `rc.auth.sessionCookieOpts`. Required if `rc` is not passed. */
		sessionCookieOpts?: Pick<SessionCookieOptions, "path" | "sameSite">
		/** From runtime config, `rc.auth.sessionExpiresAt`. Required if `rc` is not passed. */
		sessionExpiresAt?: number
		/** better-auth cookie prefix, from `rc.auth.cookiePrefix`. @default "better-auth" */
		cookiePrefix?: string
		/** Name of the cookie that records which user a window's session belongs to. @default "userId" */
		userIdCookieName?: string
		logger?: BaseLogger
		/** Called after an external login is persisted, so the app can record the user (e.g. write its user dir). */
		onFinishLogin?: (info: { win: BrowserWindow, user: { id: string, username: string } }) => void | Promise<void>
	},
	/**
	 * The auth runtime config, e.g. `rc.auth`. Takes precedence over the individual
	 * options above so they do not have to be copied over one by one.
	 */
	rc?: Pick<ModulePublicRuntimeConfig["auth"], "sessionCookieOpts" | "sessionExpiresAt" | "cookiePrefix">
	) {
		this.scheme = scheme
		this.userSchema = userSchema
		this.callbackPath = callbackPath
		this.publicServerUrl = publicServerUrl
		this.getSession = getSession
		this.getWindow = getWindow
		this.getActiveUserId = getActiveUserId
		const resolvedSessionCookieOpts = rc?.sessionCookieOpts ?? sessionCookieOpts
		const resolvedSessionExpiresAt = rc?.sessionExpiresAt ?? sessionExpiresAt
		if (!resolvedSessionCookieOpts || resolvedSessionExpiresAt === undefined) {
			throw new Error("ElectronAuth: sessionCookieOpts and sessionExpiresAt are required, pass them directly or pass rc.auth as the second argument.")
		}
		this.sessionCookieOpts = resolvedSessionCookieOpts
		this.sessionExpiresAt = resolvedSessionExpiresAt
		this.cookiePrefix = rc?.cookiePrefix ?? cookiePrefix
		this.userIdCookieName = userIdCookieName
		// better-auth names its cookies from the base url protocol, so the window's copy has to follow the same rule
		this.useSecureCookies = new URL(publicServerUrl).protocol === "https:"
		this.logger = logger
		this.onFinishLogin = onFinishLogin
	}

	/** Electron spells `sameSite: "none"` as `"no_restriction"`. */
	private get _cookieSetOpts(): Partial<CookiesSetDetails> {
		const { sameSite, ...rest } = this.sessionCookieOpts
		return sameSite ? { ...rest, sameSite: sameSite === "none" ? "no_restriction" : sameSite } : rest
	}

	private get _sessionCookieName(): string {
		return `${this.useSecureCookies ? "__Secure-" : ""}${this.cookiePrefix}.session_token`
	}

	private _parseToken(url: string): string | null {
		let parsed: URL
		try {
			parsed = new URL(url)
		} catch {
			return null
		}
		if (parsed.protocol !== `${this.scheme}:`) return null
		if (`/${parsed.hostname}${parsed.pathname}` !== this.callbackPath) return null
		if (parsed.hash.startsWith("#token=")) return parsed.hash.slice("#token=".length)
		return parsed.searchParams.get("access_token")
	}

	private async _loadCallback(win: BrowserWindow, token: string): Promise<void> {
		const windowUrl = new URL(win.webContents.getURL())
		// a custom scheme has no origin (`new URL(...).origin` is the string "null")
		const base = windowUrl.origin === "null" ? `${windowUrl.protocol}//${windowUrl.host}` : windowUrl.origin
		const url = new URL(this.callbackPath, base)
		// the page keeps its query (e.g. the provider the waiting room needs) across the load
		for (const [name, value] of windowUrl.searchParams) url.searchParams.set(name, value)
		url.searchParams.set("access_token", token)
		this.logger?.debug({ ns: "auth:deeplink" })
		await win.webContents.loadURL(url.toString())
	}

	/**
	 * Intake for scheme urls from second-instance and open-url, which only fire while the
	 * app is already open, so there is always a window and a session to load into.
	 */
	async handleUrl(url: string): Promise<boolean> {
		const token = this._parseToken(url)
		if (!token) return false
		const win = this.getWindow()
		if (!win || !this.getSession()) return false
		await this._loadCallback(win, token)
		return true
	}

	/** Window-side session cookie check for an external user. */
	async getHasCookies(): Promise<boolean> {
		const ses = this.getSession()
		if (!ses) return false
		const hasAuthCookie = (await ses.cookies.get({ name: this._sessionCookieName }))[0]
		const hasUserCookie = (await ses.cookies.get({ name: this.userIdCookieName }))[0]
		return !!(hasAuthCookie && hasUserCookie)
	}

	/**
	 * Cookie url, always the server origin. Chromium only stores cookies for
	 * http(s) schemes, so a window loaded over `app://bundle` or `file://` can
	 * never hold one. The window's session still carries the cookie, and the
	 * proxy is what sends it to the server.
	 */
	private _cookieUrl(): string {
		const { protocol, host, hostname } = new URL(this.publicServerUrl)
		if (protocol === "http:" && !["localhost", "127.0.0.1", "::1"].includes(hostname)) {
			this.logger?.warn({
				ns: "auth:cookieUrl",
				message: `publicServerUrl "${this.publicServerUrl}" is not https, the session cookie will be sent unencrypted.`
			})
		}
		if (!host || (protocol !== "http:" && protocol !== "https:")) {
			throw new Error(
				`ElectronAuth: cannot store the session cookie for publicServerUrl "${this.publicServerUrl}". Cookies need an http(s) origin, from getPaths().publicServerUrl for example.`
			)
		}
		return `${protocol}//${host}/`
	}

	/**
	 * Generic post-exchange persistence: mirrors the session cookie into the
	 * window session (`httpOnly`), the user into window `localStorage` and the
	 * cookie's expiry next to it.
	 * Returns, the app does whatever post-login it needs (user switching,
	 * folder setup, reload) after the await. No hooks, the class stays
	 * unaware of app details.
	 */
	async finishLogin(win: BrowserWindow, { user, sessionToken, expiresAt = Date.now() + this.sessionExpiresAt }: {
		user: unknown
		sessionToken: string
		/** Epoch ms, written to both cookies and to the expiry key. Defaults to `sessionExpiresAt` from now. */
		expiresAt?: number
	}): Promise<void> {
		const ses = this.getSession()
		if (!ses) throw new Error("ElectronAuth: finishLogin called before the window session existed")
		const parsedUser = this._parseUser(user)
		const cookieUrl = this._cookieUrl()
		// chromium stores the expiry in whole seconds
		const cookieExpiry = Math.floor(expiresAt / 1000)
		await ses.cookies.set({
			url: cookieUrl,
			name: this._sessionCookieName,
			value: sessionToken,
			secure: this.useSecureCookies,
			...this._cookieSetOpts,
			expirationDate: cookieExpiry,
			httpOnly: true
		})
		await ses.cookies.set({
			url: cookieUrl,
			name: this.userIdCookieName,
			value: parsedUser.id,
			secure: this.useSecureCookies,
			...this._cookieSetOpts,
			expirationDate: cookieExpiry,
			httpOnly: true
		})
		await win.webContents.executeJavaScript(
			`localStorage.setItem(${JSON.stringify(userStorageKey)}, ${JSON.stringify(JSON.stringify({ ...parsedUser, type: "external" }))});`
			+ `localStorage.setItem(${JSON.stringify(externalExpiryStorageKey)}, ${JSON.stringify(String(expiresAt))})`
		)
		this._watchSessionCookies(ses)
		this.logger?.debug({ ns: "auth:finishLogin", win: win.id })
		const { id, username } = parsedUser as { id: string, username: string }
		await this.onFinishLogin?.({ win, user: { id, username } })
	}

	/** Injects a local-only user into the window as the active user. */
	async saveLocalUserSession(win: BrowserWindow, authUser: unknown): Promise<void> {
		const parsedUser = this._parseUser(authUser)
		if (parsedUser.id !== this.getActiveUserId()) {
			throw new Error(`ElectronAuth: cannot save credentials for user ${parsedUser.id}, the active user is ${this.getActiveUserId()}.`)
		}
		await win.webContents.executeJavaScript(
			`localStorage.setItem(${JSON.stringify(userStorageKey)}, ${JSON.stringify(JSON.stringify({ ...parsedUser, type: "local" }))})`
		)
	}

	private _parseUser(value: unknown): { id: string } {
		const result = this.userSchema["~standard"].validate(value)
		if (result instanceof Promise) throw new Error("ElectronAuth: async schemas cannot parse a user.")
		if (result.issues) throw new Error(`ElectronAuth: invalid user, ${result.issues.map(issue => issue.message).join(", ")}`)
		return result.value
	}

	/**
	 * Keeps the expiry key in step with the cookie, for the session the server rolls or
	 * replaces. Chromium reports a cookie set by us as `explicit` and its removal as one of
	 * the other causes, so those are ignored and the last expiry stays, which keeps the clock
	 * comparison answering true once it has passed.
	 */
	private _watchSessionCookies(ses: Session): void {
		if (this.watchedSessions.has(ses)) return
		this.watchedSessions.add(ses)
		ses.cookies.on("changed", (_event, cookie: Cookie, cause, removed) => {
			if (removed || cause !== "explicit" || cookie.name !== this._sessionCookieName) return
			if (cookie.expirationDate === undefined) return
			const win = this.getWindow()
			if (!win) return
			const expiresAt = cookie.expirationDate * 1000
			void win.webContents.executeJavaScript(
				`localStorage.setItem(${JSON.stringify(externalExpiryStorageKey)}, ${JSON.stringify(String(expiresAt))})`
			).catch(() => undefined)
		})
	}
}
