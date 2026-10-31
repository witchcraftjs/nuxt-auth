import { electronNuxtAuthPlugin } from "#witchcraft-nuxt-auth/plugins/client/electronNuxtAuthPlugin"

export function useConfiguredAuth(): ReturnType<typeof useAuth> {
	return markRaw(useAuth({
		clientOptions: {
			// plugin gates internally, but this prevents even creating them each time
			plugins: import.meta.client ? [electronNuxtAuthPlugin()] : []
		}
	}))
}
