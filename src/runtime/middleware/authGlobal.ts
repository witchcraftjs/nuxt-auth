import { jsonSafeParse } from "@alanscodelog/utils/jsonSafeParse"

import {
	defineNuxtRouteMiddleware,
	useFetch,
	useState
} from "#imports"

import { useAuth } from "../composables/useAuth.js"
import type { AuthUserStored } from "../types.js"
import { externalExpiryStorageKey, fetchStateKey, isExpiredStateKey, userStorageKey } from "../types.js"
import { deserializeAuthLocalUser } from "../utils/deserializeAuthLocalUser.js"

export default defineNuxtRouteMiddleware(async (_to, _from) => {
	const auth = useAuth()
	const doFetch = useState(fetchStateKey, () => true)
	const userData = useState(userStorageKey, () => undefined as any)
	const isExpired = useState(isExpiredStateKey, () => false)

	if (import.meta.client && import.meta.dev) {
		// eslint-disable-next-line no-console
		console.log({ ns: "auth:middleware:authGlobal", doFetch: doFetch.value, userData: userData.value })
	}

	/**
	 *
	 * On the client:
	 *
	 * Read storage first, and use a user that carries a `type` as is.
	 *
	 * 	- electron main writes it after the session exchange, and the
	 * 	- local users plugin writes it on creation
	 *
	 * It also stops the next navigation waiting on the network.
	 *
	 * `doFetch` overrides that, because it is the app saying the server has news: after a login or a registration the stored copy is stale until the session is read again.
	 *
	 * On the server the session is always checked.
	 */
	const stored = import.meta.client
		? jsonSafeParse(localStorage.getItem(userStorageKey) ?? "null")
		: undefined
	const storedUser = stored?.isOk && stored.value ? deserializeAuthLocalUser(stored.value as AuthUserStored) : undefined

	if (doFetch.value) {
		doFetch.value = false
		if (import.meta.server) {
			const session = await auth.client.useSession(useFetch)
			userData.value = session?.data.value?.user ?? undefined
		} else {
			const { data } = await auth.client.getSession().catch(() => ({ data: undefined }))
			// getSession types the dates as Date, the JSON response carries ISO strings
			const sessionUser = data?.user ? deserializeAuthLocalUser(data.user as unknown as AuthUserStored) : undefined
			/**
			 * An external user keeps their `type` through the refresh, since the server never
			 * sends one. Without it the client would stop treating them as external for the
			 * rest of the session, and the stored copy is refreshed too because it is what the
			 * next navigation reads.
			 */
			if (sessionUser && storedUser?.type === "external") {
				userData.value = { ...sessionUser, type: "external" }
				localStorage.setItem(userStorageKey, JSON.stringify(userData.value))
				if (data?.session?.expiresAt) {
					localStorage.setItem(externalExpiryStorageKey, String(new Date(data.session.expiresAt).getTime()))
				}
			} else {
				userData.value = sessionUser ?? storedUser
			}
		}
	} else if (storedUser?.type) {
		userData.value = storedUser
	}

	/**
	 * Written on every client navigation because the question is asked by actions, not by
	 * the page load, and the session can end while the app runs. False on the server.
	 */
	if (import.meta.client) {
		isExpired.value = userData.value?.type === "external" ? auth.isExpired() : false
	}

	if (import.meta.client && import.meta.dev) {
		// eslint-disable-next-line no-console
		console.log({
			ns: "auth:middleware:authGlobal:fetched",
			userData: userData.value,
			isExpired: isExpired.value
		})
	}
})
