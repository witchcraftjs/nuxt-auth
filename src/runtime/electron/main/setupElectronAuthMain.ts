import { electronClient } from "@better-auth/electron/client"
import { storage } from "@better-auth/electron/storage"
import type { StandardSchemaV1 } from "@standard-schema/spec"
import { type BetterAuthClientOptions, createAuthClient } from "better-auth/client"
import { defuArrayFn } from "defu"
import { type BrowserWindow, ipcMain, type Session, shell } from "electron"
import { createHash, randomBytes } from "node:crypto"

import { ElectronAuth } from "./ElectronAuth.js"

import type { ModulePublicRuntimeConfig } from "../../../module.js"
import type { AuthUser } from "../../types.js"
import { exchangeSessionChannel, mockRequestAuthChannel } from "../types.js"

/** Whether the renderer asked for the mock. better-auth serializes `additionalParams` into the url as JSON. */
// llm: i thought we stopped using this
function hasDevBypassParams(url: URL): boolean {
	const raw = url.searchParams.get("additionalParams")
	if (!raw) return false
	try {
		return (JSON.parse(raw) as { devBypass?: string }).devBypass === "true"
	} catch {
		return false
	}
}

/**
 * Wires the main process side of an electron sign-in by setting up:
 * - the better-auth client the preload bridges talk to
 * - deeplink handling
 * - the handlers for the preload APIs
 * - mocking handlers (for a full mock with registration bypass always true, no browser side mocking) if TEST is true (can be disabled via `enableMockingInTestEnvs: false`
 *
 * It does not setup scheme registration or CSP.
 *
 * Call it once, before `app.whenReady()`.
 */
export function setupElectronAuthMain(
	rc: ModulePublicRuntimeConfig["auth"],
	{
		publicServerUrl,
		getSession,
		userSchema,
		getWindow,
		getActiveUserId,
		clientOptions,
		userIdCookieName,
		enableMockingInTestEnvs = true,
		onFinishLogin
	}: {
		/** Public server url of the better-auth server, e.g. `getPaths().publicServerUrl`. */
		publicServerUrl: string
		/** Returns the session the window uses, e.g. `() => ses`, undefined until the window is created. Its cookies are what the proxy sends. */
		getSession: () => Session | undefined
		/**
		 * Parses the user before it is written to the window, e.g. `zAuthUserStored`.
		 * Build it from the db table so there is one source of truth for the user shape.
		 */
		userSchema: StandardSchemaV1<unknown, { id: string }>
		/** Returns the window the bridges act on, null when none exists yet. */
		getWindow: () => BrowserWindow | null | undefined
		/** Returns the id of the user the app treats as active, e.g. `() => activeUserId`. */
		getActiveUserId: () => string | undefined
		/** Add options to the better-auth client, deep-merged (via `defuArrayFn`) over the options built here. */
		clientOptions?: BetterAuthClientOptions
		/** Name of the cookie that records which user a window's session belongs to. @default "userId" */
		userIdCookieName?: string
		/** Called after an external login is persisted, so the app can record the user (e.g. write its user dir). */
		onFinishLogin?: (ctx: {
			win: BrowserWindow
			user: { id: string, username: string | null }
		}) => void | Promise<void>
		/**
		 * Enables mocking when TEST is true.
		 *
		 * @default true
		 */
		enableMockingInTestEnvs?: boolean
	}
) {
	const mockSignInUrl = `${publicServerUrl}${rc.authRoutes.mockAuth}`
	const isMocked = enableMockingInTestEnvs && process.env.TEST === "true" && !!rc.devBypassAuth
	const signInUrl = isMocked ? mockSignInUrl : `${publicServerUrl}${rc.authRoutes.login}`

	const client = createAuthClient(defuArrayFn(clientOptions ?? {}, {
		baseURL: publicServerUrl,
		// better-auth checks the origin once a request carries a session cookie, and main sends none
		fetchOptions: { headers: { origin: publicServerUrl } },
		plugins: [
			electronClient(
				{
					channelPrefix: "better-auth",
					protocol: { scheme: rc.deeplinkSchemes.electron! },
					callbackPath: rc.authRoutes.deeplink!,
					cookiePrefix: rc.cookiePrefix,
					signInURL: signInUrl,
					storage: storage(),
					/* Disabled because the proxy registers its own scheme with protocol.registerSchemesAsPrivileged, and electron only honours the last of those calls: a second one replaces the first, so the app's scheme loses standard and secure and its window stops being a secure context, which also removes crypto.randomUUID from the page. It's not needed anyways since our proxy means we can directly load server image urls. */
					userImageProxy: { enabled: false }
				}
			)
		]
	}))

	client.setupMain({ bridges: true, csp: false, scheme: false, getWindow })

	const electronAuth = new ElectronAuth({
		scheme: rc.deeplinkSchemes.electron!,
		userSchema,
		callbackPath: rc.authRoutes.deeplink!,
		publicServerUrl,
		getSession,
		getWindow,
		getActiveUserId,
		userIdCookieName,
		onFinishLogin
	}, rc)

	// the cookie name has to match the server's, so it follows the server origin, not the build environment
	const cookieName = `${new URL(publicServerUrl).protocol === "https:" ? "__Secure-" : ""}${rc.cookiePrefix}.session_token`

	ipcMain.removeHandler(exchangeSessionChannel)
	ipcMain.handle(exchangeSessionChannel, async () => {
		const win = getWindow()
		if (!win) return

		const entry = client.getCookie()
			.split(";")
			.map(part => part.trim())
			.find(part => part.startsWith(`${cookieName}=`))
		if (!entry) return

		const { data } = await client.$fetch<{ user: unknown, session: { expiresAt: string } }>("/get-session")
		if (!data?.user) return

		// better-auth revives the session's dates so we have to reconvert back
		const received = data.user as AuthUser
		const user = {
			...received,
			createdAt: received.createdAt.toISOString(),
			updatedAt: received.updatedAt.toISOString()
		}

		await electronAuth.finishLogin(win, {
			user,
			sessionToken: entry.slice(cookieName.length + 1),
			expiresAt: new Date(data.session.expiresAt).getTime()
		})
	})

	if (isMocked) {
		let pendingMockIdentity: { username?: string, id?: string, devBypassRegistration?: boolean } = {}

		/**
		 * The test's stand-in for starting a provider login.
		 *
		 * It mints the same challenge and opens the same kind of url a real login does, but the user comes from the test instead of the provider. The verifier is put where the token exchange looks for it, so that half stays untouched.
		 *
		 * Same steps as better-auth's own `requestAuth`, keep them in sync.
		 */
		ipcMain.handle(mockRequestAuthChannel, async (_event, identity: { username?: string, id?: string, provider?: string, devBypassRegistration?: boolean }) => {
			if (!identity.provider) {
				throw new Error("mockRequestAuth: a provider is required, it has to be one of the configured providers.")
			}
			pendingMockIdentity = identity

			const state = randomBytes(16).toString("base64url")
			const codeVerifier = randomBytes(32).toString("base64url")
			const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url")

			// the store better-auth's `authenticate` reads the verifier from
			const mockStore = globalThis as any
			const verifiers = mockStore[Symbol.for("better-auth:electron")] ?? new Map()
			mockStore[Symbol.for("better-auth:electron")] = verifiers
			verifiers.set(state, codeVerifier)

			const url = new URL(signInUrl)
			url.searchParams.set("provider", identity.provider)
			url.searchParams.set("additionalParams", JSON.stringify({ devBypass: "true" }))
			url.searchParams.set("client_id", "electron")
			url.searchParams.set("code_challenge", codeChallenge)
			url.searchParams.set("state", state)

			await shell.openExternal(url.toString())
		})
		const openExternal = shell.openExternal.bind(shell)
		shell.openExternal = async url => {
			if (!url.startsWith(publicServerUrl)) return openExternal(url)
			const target = new URL(url)

			// the mock page itself, or the provider request a real login would send the browser to
			const isMockPage = target.pathname === rc.authRoutes.mockAuth
			const isProviderRequest = target.pathname.endsWith("/electron/init-oauth-proxy")
			if (!isMockPage && !isProviderRequest) return openExternal(url)
			if (!hasDevBypassParams(target)) return openExternal(url)

			const provider = target.searchParams.get("provider")
			const codeChallenge = target.searchParams.get("code_challenge")
			const state = target.searchParams.get("state")
			if (!provider || !codeChallenge || !state) return

			const { data } = await client.$fetch<{ redirectUrl: string }>("/dev/mock", {
				method: "POST",
				body: {
					provider,
					username: pendingMockIdentity.username,
					id: pendingMockIdentity.id,
					devBypassRegistration: pendingMockIdentity.devBypassRegistration ?? false,
					client_id: "electron",
					code_challenge: codeChallenge,
					state,
					verification_prefix: "electron",
					deeplink_scheme: rc.deeplinkSchemes.electron
				}
			})
			if (!data?.redirectUrl) return
			await electronAuth.handleUrl(data.redirectUrl)
		}
	}

	return { client, electronAuth }
}
