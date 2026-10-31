import type { Ref } from "vue"
import { ref } from "vue"

import {
	$fetch,
	navigateTo,
	useRoute,
	useRuntimeConfig
} from "#imports"

/**
 * The mock stands in for the provider's login acceptance page, which only exists on the web, so electron should never render it.
 *
 * It supports electron because a built and *installed* app can receive the deeplink so technically an testing app can be configured for a browser side mocked flow, but this is usually not done because it involves the install of a desktop file.
 *
 * The playground tests, for example do not build and install the app, so they set the same things from the login page instead.
 */
export function useAuthMocker({
	deeplinkScheme = useRuntimeConfig().public.auth.deeplinkSchemes?.electron
}: {
	/** Scheme of the deeplink the mock redirects to, from `rc.auth.deeplinkSchemes`. Defaults to the electron scheme. */
	deeplinkScheme?: string
} = {}) {
	const route = useRoute()
	const username: Ref<string> = ref("")
	const bypassRegistration: Ref<boolean> = ref(false)

	const provider = route.query.provider
	if (!provider || typeof provider !== "string") {
		throw new Error("Missing provider query param.")
	}

	async function submit() {
		const rc = useRuntimeConfig().public
		const { redirectUrl } = await $fetch<{ redirectUrl: string }>(
			`${rc.auth.authApiRouteBase}/dev/mock`,
			{
				method: "POST",
				body: {
					provider,
					// a user who does not bypass registration has no username to choose yet
					username: bypassRegistration.value ? username.value : undefined,
					devBypassRegistration: bypassRegistration.value,
					code_challenge: route.query.code_challenge,
					state: route.query.state,
					deeplink_scheme: deeplinkScheme
				}
			}
		)

		await navigateTo(redirectUrl, { external: true })
	}

	return {
		provider,
		username,
		bypassRegistration,
		submit
	}
}
