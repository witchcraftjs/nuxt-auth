import { electronProxyClient } from "@better-auth/electron/proxy"
import type { StandardSchemaV1 } from "@standard-schema/spec"
import type { BetterAuthClientOptions } from "better-auth"
import { inferAdditionalFields, usernameClient } from "better-auth/client/plugins"
import { createAuthClient } from "better-auth/vue"
import { defu } from "defu"

import {
	navigateTo,
	useRequestHeaders,
	useRequestURL,
	useRuntimeConfig,
	useState
} from "#app"
import { computed } from "#imports"

import { localOnlyUsers } from "../plugins/client/localOnlyUsers.js"
import type { AuthUser, ExternalPlugin } from "../types.js"
import { defaultZodUsernameSchema, externalExpiryStorageKey, fetchStateKey, userStorageKey } from "../types.js"

type AuthListenerHook = (options: { scope?: "all" | "others" }) => void
type AuthListenerHooks = "beforeLogout" | "beforeDelete" | "afterDelete"
const hooks = {
	beforeLogout: [] as AuthListenerHook[],
	beforeDelete: [] as (({ id }: { id: string }) => void)[],
	afterDelete: [] as (({ id }: { id: string }) => void)[]
}

export const useAuth = ({ usernameSchema = defaultZodUsernameSchema, userSchema, clientOptions }: {
	/** Username schema used when a local-only user checks availability locally. */
	usernameSchema?: StandardSchemaV1<string, string>
	/** Validates users read from storage, e.g. `zAuthUserStored`. */
	userSchema?: StandardSchemaV1
	/** Options passed to the better-auth client in full, merged over the module defaults with `defu`. */
	clientOptions?: BetterAuthClientOptions
} = {}) => {
	const config = useRuntimeConfig().public.auth as any
	const doFetch = useState(fetchStateKey)
	const userData = useState(userStorageKey, () => undefined as AuthUser | undefined)
	const isAuthenticated = computed(() => !!userData.value)
	const isRegistered = computed(() => !!userData.value?.isRegistered)
	const authRoutes = {
		...config.authRoutes,
		login: config.authRoutes.login
	}

	const defaultClientOptions = {
		baseURL: import.meta.server ? useRequestURL().origin : config.publicServerUrl,
		fetchOptions: {
			headers: import.meta.server ? useRequestHeaders(["cookie"]) : undefined,
			// on electron, the relative paths used resolve to app://... instead of publicServerUrl
			// this would be fine (electron proxies the requests to the app) except better auth errors on such a schema
			// so we have to write the url for it to fetch from
			customFetchImpl: config.publicServerUrl
				? (input: any, init?: any) => {
						const url = new URL(
							typeof input === "string" ? input : input.url ?? String(input),
							config.publicServerUrl
						)
						return fetch(`${url.pathname}${url.search}`, init)
					}
				: undefined
		},
		plugins: [
			...(config.deeplinkSchemes?.electron
				// unlike the plugin we provide, this one is harmless to add as nothing of ours automatically calls it
				// same thing if we add other platforms in the future
				? [electronProxyClient({
						protocol: config.deeplinkSchemes.electron,
						callbackPath: config.authRoutes.deeplink,
						cookiePrefix: config.cookiePrefix
					})]
				: []),
			usernameClient(),
			inferAdditionalFields({
				user: {
					isRegistered: { type: "boolean" }
				}
			}),
			localOnlyUsers({
				userSchema
			})
		]
	}
	const merged = defu(clientOptions, defaultClientOptions)
	const client = createAuthClient(merged as typeof defaultClientOptions)

	function getExternal(): ExternalPlugin | undefined {
		if (import.meta.server) return undefined
		for (const plugin of merged.plugins ?? []) {
			const key = "externalApiActionsKey" in plugin ? plugin.externalApiActionsKey : undefined
			if (typeof key !== "string") continue
			const actions = (client as unknown as Record<string, ExternalPlugin>)[key]!
			if (actions.isActive() === true && typeof actions.login === "function") return actions
		}
		return undefined
	}
	const external = getExternal()
	const isExternal = computed(() => external !== undefined)

	function setFetchUserOnNavigation(value: boolean = true): void {
		doFetch.value = value
	}

	function assertIsOnClient(method: string): void {
		if (import.meta.server) throw new Error(`${method}: only available in the browser.`)
	}

	async function login(provider: string, {
		devBypass = false,
		devBypassRegistration = false,
		username
	}: {
		/** Send the request with the devBypass query param (This will only actually bypass auth if the server permits it). */
		devBypass?: boolean
		/** Create the mock user already registered, so the app skips the registration page. */
		devBypassRegistration?: boolean
		/** The username to sign in as when using dev bypass, or the stored local user to sign in to (required when `provider` is `local`). */
		username?: string
	} = {}): Promise<void> {
		if (provider === "local") {
			assertIsOnClient("login")
			if (username === undefined) throw new Error("login: signing in to a local user needs a username.")
			const stored = external?.local ? await external.local.list() : client.localOnlyUsers.list()
			const entry = stored.find(item => item.username === username)
			if (!entry) {
				const parsed = await usernameSchema["~standard"].validate(username)
				if (parsed.issues) throw new Error(`login: cannot create a local user, "${username}" is not a valid username.`)
			}
			// an external switches user outside the app, so no navigation is done here
			if (external?.local) {
				if (entry) await external.local.activate(entry.id)
				else await external.local.create({ id: crypto.randomUUID(), username })
				return
			}
			if (entry) client.localOnlyUsers.activate(username)
			else client.localOnlyUsers.create(username)
			await navigateTo(authRoutes.postRegisteredLogin)
			return
		}
		// must happen AFTER local user handling
		setFetchUserOnNavigation()
		if (external) {
			await external.login({
				provider,
				isDevBypass: devBypass,
				username,
				isDevBypassRegistration: devBypassRegistration
			})
			return
		}
		if (devBypass) {
			await navigateTo(`${authRoutes.mockAuth}?provider=${provider}`)
			return
		}
		if (userData.value) throw new Error("login is not available while a user is signed in.")
		await client.signIn.social({
			provider,
			callbackURL: authRoutes.postRegisteredLogin
		})
	}

	async function logout({ scope }: { scope?: "all" | "others" } = {}): Promise<void> {
		assertIsOnClient("logout")
		setFetchUserOnNavigation()

		const isLocal = userData.value?.type === "local"

		await Promise.allSettled(hooks.beforeLogout.map(listener => listener({ scope })))

		if (scope === "others") {
			if (!isLocal) {
				await client.revokeOtherSessions()
			}
			return
		}

		if (isLocal) {
			client.localOnlyUsers.logout()
		}

		if (!isLocal) {
			await (scope === "all" ? client.revokeSessions() : client.signOut())
				.catch(() => undefined)
				.finally(() => navigateTo(authRoutes.unauthenticated, { external: true }))
		}
		userData.value = undefined
		localStorage.removeItem(externalExpiryStorageKey)
		await navigateTo(authRoutes.unauthenticated, { external: true })
	}

	/**
	 * When a user is external, whether the active user's session is known to be expired. A user with no stored expiry has none known, so this answers false.
	 *
	 * Throws for non-external users.
	 */
	function isExpired(): boolean {
		assertIsOnClient("isExpired")
		const type = userData.value?.type
		if (type !== "external") {
			throw new Error(`isExpired: only an external user has an expiry, the active user is ${type ?? "a server user"}.`)
		}
		const expiresAt = localStorage.getItem(externalExpiryStorageKey)
		if (!expiresAt) return false
		return Date.now() >= Number(expiresAt)
	}

	/**
	 * Deletes the active user, or a local user when an id is given. Any other id throws: an id can
	 * only name a local user, or the active user.
	 */
	async function deleteUser(id?: string): Promise<void> {
		const current = userData.value
		if (id !== undefined && current?.type === "external" && id !== current.id) {
			throw new Error("delete: an id can only name a local user, or the active user.")
		}
		const target = id ?? current?.id
		if (!target) throw new Error("delete: there is no active user and no id was given.")
		const isLocal = target === current?.id ? current.type === "local" : true

		setFetchUserOnNavigation()

		await Promise.allSettled(hooks.beforeDelete.map(listener => listener({ id: target })))

		if (isLocal) {
			assertIsOnClient("delete")
			if (external?.local) await external.local.delete(target)
			else client.localOnlyUsers.delete(target)
		} else {
			await client.deleteUser()
		}
		if (target === current?.id) {
			userData.value = undefined
			await navigateTo(authRoutes.unauthenticated, { external: true })
		}
		await Promise.allSettled(hooks.afterDelete.map(listener => listener({ id: target })))
	}

	async function update(patch: { username?: string, name?: string, image?: string }): Promise<void> {
		const current = userData.value
		if (!current) throw new Error("update: there is no active user.")

		if (current.type === "local") {
			assertIsOnClient("update")
			if (external?.local) {
				await external.local.update(current.id, patch)
				return
			}
			const updated = client.localOnlyUsers.update(current.id, patch)
			if (!updated) throw new Error("update: the stored user no longer exists.")
			return
		}

		await client.updateUser(patch, { throw: true })
		await external?.onUserUpdate(current.id, patch)
	}

	async function isUsernameAvailable({ username, local }: { username: string, local: boolean }): Promise<boolean> {
		if (!local) return (await client.isUsernameAvailable({ username }, { throw: true })).available
		assertIsOnClient("isUsernameAvailable")

		const parsed = await usernameSchema["~standard"].validate(username)
		if (parsed.issues) return false

		const users = external?.local ? await external.local.list() : client.localOnlyUsers.list()
		return !users.some(entry => entry.username === parsed.value)
	}

	async function list(): Promise<AuthUser[]> {
		assertIsOnClient("list")
		if (external?.local) return await external.local.list()
		return client.localOnlyUsers.list()
	}

	function on<TKey extends AuthListenerHooks>(hook: TKey, listener: (typeof hooks)[TKey][number]): void {
		(hooks[hook] as unknown as ((options: any) => void)[]).push(listener)
	}
	function off<TKey extends AuthListenerHooks>(hook: TKey, listener: (typeof hooks)[TKey][number]): void {
		const listeners = hooks[hook] as unknown as ((options: any) => void)[]
		const index = listeners.indexOf(listener)
		if (index > -1) {
			listeners.splice(index, 1)
		}
	}


	return {
		on,
		off,
		user: userData,
		setFetchUserOnNavigation,
		login,
		logout,
		authRoutes,
		isAuthenticated,
		isRegistered,
		isExpired,
		isExternal,
		delete: deleteUser,
		update,
		isUsernameAvailable,
		list,
		client
	}
}
