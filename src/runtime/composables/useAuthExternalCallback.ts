import { ref } from "vue"

import { useAuth } from "./useAuth.js"

import {
	navigateTo,
	useRoute,
	useRuntimeConfig
} from "#app"

import type { AuthUserStored } from "../types.js"
import { deserializeAuthLocalUser } from "../utils/deserializeAuthLocalUser.js"

export type ExternalCallbackOptions = {
	/** Trades the token for a session, e.g. `window.authenticate` from the preload bridge. */
	authenticate: (token: string) => Promise<unknown>
	/** Starts the login again while there is no token, supplied by the app for its platform. */
	requestExternalAuth: (options: { provider?: string }) => Promise<void>
	/** Path to navigate to on success. Defaults to `postRegisteredLogin` from runtime config. */
	successPath?: string
	/** Path to navigate to on cancel. Defaults to `login` from runtime config. */
	cancelPath?: string
}

/**
 * Reads the token from the deeplink route (fragment `#token=` or
 * `?access_token=`) or a manual paste box, then trades it for a session.
 */
export function useAuthExternalCallback(opts: ExternalCallbackOptions) {
	const rc = useRuntimeConfig()
	const route = useRoute()

	const hashToken = typeof window !== "undefined" && window.location.hash.startsWith("#token=")
		? window.location.hash.slice("#token=".length)
		: undefined
	const queryToken = typeof route.query.access_token === "string" ? route.query.access_token : undefined
	const initialAccessToken = hashToken ?? queryToken
	const provider = typeof route.query.provider === "string" ? route.query.provider : undefined

	const bridge = opts.requestExternalAuth
	const { client } = useAuth()

	const manualAccessToken = ref("")
	const error = ref<string | undefined>(undefined)

	if (initialAccessToken) {
		void authorize(initialAccessToken, true)
	}

	async function authorize(accessToken?: string, isInitial = false) {
		if (!accessToken || accessToken.length === 0) {
			if (!isInitial) {
				error.value = "No code provided."
			}
			return
		}
		try {
			await opts.authenticate(accessToken)
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err)
			return
		}
		/**
		 * The session the exchange just made is the authority: a user who still has to
		 * register goes there instead, which is what the browser flow does on the server
		 * side. A failed read, or no user at all, keeps the post login route.
		 */
		const { data } = await client.getSession().catch(() => ({ data: undefined }))
		// getSession types the dates as Date, the JSON response carries ISO strings
		const user = data?.user ? deserializeAuthLocalUser(data.user as unknown as AuthUserStored) : undefined
		const routes = (rc.public as any).auth.authRoutes
		const successPath = user && user.isRegistered === false ? routes.register : routes.postRegisteredLogin
		await navigateTo(opts.successPath ?? successPath)
	}

	/** Starts the login over, so a second attempt gets a fresh challenge and state. */
	async function requestExternalAuth(): Promise<void> {
		await bridge({ provider }).catch((err: unknown) => {
			error.value = err instanceof Error ? err.message : String(err)
		})
	}

	async function cancel() {
		await navigateTo(opts.cancelPath ?? (rc.public as any).auth.authRoutes.login)
	}

	return {
		initialAccessToken,
		manualAccessToken,
		error,
		authorize,
		requestExternalAuth,
		cancel
	}
}
