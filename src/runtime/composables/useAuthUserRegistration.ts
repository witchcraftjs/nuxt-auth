import type { StandardSchemaV1 } from "@standard-schema/spec"
import { refDebounced } from "@vueuse/core"
import { useAsyncValidation } from "@witchcraft/nuxt-utils/composables/useAsyncValidation"
import { computed, ref } from "vue"

import { navigateTo, useRoute, useRuntimeConfig } from "#app"

import { useAuth } from "../composables/useAuth.js"
import { defaultZodUsernameSchema, usernameValidFetchKey } from "../types.js"

/**
 * Wraps all the async username validation and registration logic.
 *
 * Uses {@link useAsyncValidation} from `@witchcraft/nuxt-utils` under the hood.
 *
 * Notes:
 * - Remember to gate the button with `v-if` canSubmit.
 * - If wrapping handleSubmit, also remember to check `canSubmit` first.
 * - inputValid is only a visual indicator and is valid for empty inputs and when the server is validating a request. Username might still be invalid.
 */
export function useAuthUserRegistration({
	auth = useAuth(),
	debounce = 1000,
	statusTextMap = {
		loading: "Checking availability...",
		valid: "Username available.",
		invalid: "Username unavailable."
	},
	usernameSchema = defaultZodUsernameSchema
}: {
	/** The auth instance to use, so a caller can hand in one that carries its platform plugins. */
	auth?: ReturnType<typeof useAuth>
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
		usernameValidFetchKey,
		`${useRuntimeConfig().public.auth.authApiRouteBase}/username/valid`,
		submitErrors,
		{
			debounce: 0, // we already debounced
			statusTextMap,
			schema: usernameSchema,
			getFetchOptions: () => ({
				query: {
					username: debouncedUsername.value
				}
			})
		}
	)


	const deeplink = typeof query.deeplink === "string" ? query.deeplink : undefined
	const redirectUrl = deeplink
		? config.auth.authRoutes.externalCode
		: config.auth.authRoutes.postRegisteredLogin

	if (!redirectUrl) throw new Error("No externalCode or postRegisteredLogin route defined.")

	async function handleSubmit(_event: Event) {
		if (!canSubmit.value) return
		submitErrors.value = []
		await auth.update({ username: username.value })
			.catch((e: any) => {
				submitErrors.value = [`Registration Error: ${e?.message ?? e}`]
			})
		if (submitErrors.value.length > 0) return
		auth.setFetchUserOnNavigation(true)
		await navigateTo(redirectUrl, { external: true })
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
