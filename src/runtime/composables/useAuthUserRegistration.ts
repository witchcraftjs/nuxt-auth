import type { StandardSchemaV1 } from "@standard-schema/spec"
import { refDebounced } from "@vueuse/core"
import { useAsyncValidation } from "@witchcraft/nuxt-utils/composables/useAsyncValidation"
import type { NitroFetchOptions, NitroFetchRequest } from "nitropack"
import { computed, ref } from "vue"

import { navigateTo, useRoute, useRuntimeConfig } from "#app"

import { useAuth } from "../composables/useAuth.js"
import { AUTH_ERROR, defaultZodUsernameSchema } from "../types.js"
import { getAuthApiRoute } from "../utils/getAuthApiRoute.js"

/**
 * Wraps all the async username validation and registration logic.
 *
 * Uses {@link useAsyncValidation} from `@witchcraft/nuxt-utils` under the hood.
 *
 * Notes:
 * - Remember to gate the button with `v-if` canSubmit.
 * - If wrapping handleSubmit, also remember to check `canSubmit` first. Prefer using modifyFetch if you need to add something to the request.
 * - inputValid is only a visual indicator and is valid for empty inputs and when the server is validating a request. Username might still be invalid.
 */
export function useAuthUserRegistration({
	modifyFetch,
	debounce = 1000,
	statusTextMap = {
		loading: "Checking availability...",
		valid: "Username available.",
		invalid: "Username unavailable."
	},
	usernameSchema = defaultZodUsernameSchema
}: {
	modifyFetch?: (request: {
		cache: "no-store"
		method: "post"
		body: { username: string }
	}) => NitroFetchOptions<NitroFetchRequest, any>
	debounce?: number
	usernameSchema?: StandardSchemaV1<string, string>
	statusTextMap?: {
		loading: string
		valid: string
		invalid: string
	}
} = {}) {
	const config = useRuntimeConfig().public
	const query = useRoute().query

	const username = ref("")
	const debouncedUsername = refDebounced(username, debounce)
	const submitErrors = ref<string[]>([])

	const {
		errors,
		status,
		statusText,
		canSubmit,
		inputValid,
		_internal
	} = useAsyncValidation(
		debouncedUsername,
		"auth:username:valid",
		getAuthApiRoute(
			config,
			"usernameValid"
		),
		submitErrors,
		{
			debounce: 0, // we already debounced
			statusTextMap,
			schema: usernameSchema
		}
	)


	const deeplink = typeof query.deeplink === "string" ? query.deeplink : undefined
	const redirectUrl = deeplink
		? config.auth.authRoutes.externalCode
		: config.auth.authRoutes.register

	if (!redirectUrl) throw new Error("No externalCode or register route defined.")

	async function handleSubmit(_event: Event) {
		if (!canSubmit.value) return
		let request: NitroFetchOptions<NitroFetchRequest, any> = {
			cache: "no-store",
			method: "post",
			body: { username: username.value }
		}

		if (modifyFetch) request = modifyFetch(request as any)

		const res = await $fetch<true | { redirectUrl: string }>(`${getAuthApiRoute(config, "register")}${deeplink ? `?deeplink=${deeplink}` : ""}`, request).catch(async e => {
			submitErrors.value = [`Registration Error: ${e.data.message}`]

			if (e?.data?.code === AUTH_ERROR.USER_ALREADY_REGISTERED) {
				useAuth().setFetchUserOnNavigation(true)
				await navigateTo(redirectUrl, { external: true })
			}
		})

		if (typeof res === "object" && res.redirectUrl) {
			await navigateTo(res.redirectUrl, { external: true })
		}
	}
	const isDebouncing = computed(() => debouncedUsername.value !== username.value)

	return {
		username,
		errors,
		status,
		statusText,
		canSubmit,
		handleSubmit,
		inputValid,
		isDebouncing,
		_internal
	}
}
