import type { Ref } from "vue"
import { ref } from "vue"

import {
	navigateTo,
	useRoute,
	useRuntimeConfig
} from "#imports"

import { getAuthApiRoute } from "../utils/getAuthApiRoute.js"

export function useAuthMocker() {
	const route = useRoute()
	const username: Ref<string> = ref("")
	const bypassRegistration: Ref<boolean> = ref(false)

	const provider = route.query.provider
	if (!provider || typeof provider !== "string") {
		throw new Error("Missing provider query param.")
	}


	async function submit() {
		const query = route.query
		delete query.provider
		const callbackRoute = getAuthApiRoute(useRuntimeConfig().public, "callback", { provider: provider as string }, {
			devBypass: true,
			username: username.value,
			devBypassRegistration: bypassRegistration.value,
			...query
		})
		await navigateTo(callbackRoute, { external: true })
	}

	return {
		provider,
		username,
		bypassRegistration,
		submit
	}
}
