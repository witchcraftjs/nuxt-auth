import {
	navigateTo,
	useRuntimeConfig,
	useState
} from "#app"
import type { AuthUser, ProviderNames, UseAuthComposableOptions } from "#auth/types.js"
import { computed } from "#imports"

import { getAuthApiRoute } from "../utils/getAuthApiRoute.js"

type AuthListenerHook = () => void
type AuthListenerHooks = "beforeLogout"
const hooks: Record<AuthListenerHooks, AuthListenerHook[]> = {
	beforeLogout: []
}

export const useAuth = ({ handleActions }: UseAuthComposableOptions = {}) => {
	const config = useRuntimeConfig().public.auth
	const doFetch = useState("auth:_fetch")
	const userData = useState("auth:user", () => null as AuthUser | null)
	const isSemiAuthed = useState("auth:semiAuthed", () => false)
	const isAuthenticated = computed(() => !!userData.value)
	const isRegistered = computed(() => !!userData.value?.isRegistered)
	const authRoutes = {
		...config.authRoutes,
		login: config.authRoutes.login
	}

	function setFetchUserOnNavigation(value: boolean = true): void {
		doFetch.value = value
	}

	async function login(provider: ProviderNames, {
		devBypass = false
	}: {
		/** Send the request with the devBypass query param (This will only actually bypass auth if the server permits it). */
		devBypass?: boolean
	} = {}): Promise<void> {
		setFetchUserOnNavigation()
		const loginRoute = getAuthApiRoute(useRuntimeConfig().public, "login", { provider: provider.toLowerCase() }, { devBypass })
		const external = provider ? true : undefined
		let handled = handleActions?.("login", loginRoute, provider)
		if (handled instanceof Promise) handled = await handled

		if (!handled) {
			await navigateTo(loginRoute, { external })
		}
	}
	async function logout(): Promise<void> {
		setFetchUserOnNavigation()
		userData.value = null

		await Promise.allSettled(hooks.beforeLogout.map(listener => listener()))
		const handled = handleActions?.("logout", getAuthApiRoute(useRuntimeConfig().public, "logout"))
		if (!handled) {
			const res = await $fetch(getAuthApiRoute(useRuntimeConfig().public, "logout"), {
				cache: "no-store",
				method: "post"
			})
			if (res) {
				// using external so it forces a reload to clear any state (e.g. indexeddb doesn't properly close until reload sometimes)
				await navigateTo(authRoutes.unauthenticated, { external: true })
			}
		}
	}

	async function on(hook: AuthListenerHooks, listener: AuthListenerHook): Promise<void> {
		hooks[hook].push(listener)
	}
	async function off(hook: AuthListenerHooks, listener: AuthListenerHook): Promise<void> {
		const index = hooks[hook].indexOf(listener)
		if (index > -1) {
			hooks[hook].splice(index, 1)
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
		isSemiAuthed
	}
}
