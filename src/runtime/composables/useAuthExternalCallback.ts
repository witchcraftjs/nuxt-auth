import type { Ref } from "vue"
import { ref } from "vue"
import z from "zod"

import {
	navigateTo,
	useRoute,
	useRuntimeConfig
} from "#app"

import { zExternalCallbackPageQuery } from "../types.js"

export type ExternalCallbackOptions = {
/** Called with the access token to create a session. */
	saveSession: (accessToken: string) => Promise<void>
	/** Path to navigate to on success. Defaults to `postRegisteredLogin` from runtime config. */
	successPath?: string
	/** Path to navigate to on cancel. Defaults to `login` from runtime config. */
	cancelPath?: string

}
export function useAuthExternalCallback(
	opts: ExternalCallbackOptions
) {
	const rc = useRuntimeConfig()
	const query = useRoute().query

	const parsedQuery = zExternalCallbackPageQuery.safeParse(query)
	if (parsedQuery.error) throw new Error(z.prettifyError(parsedQuery.error))
	const initialAccessToken = "accessToken" in parsedQuery.data ? parsedQuery.data.accessToken : undefined
	const authUri = "authUri" in parsedQuery.data ? parsedQuery.data.authUri : undefined

	if (initialAccessToken) {
		void authorize(initialAccessToken, true)
	}

	const manualAccessToken: Ref<string> = ref("")
	const error: Ref<string | undefined> = ref(undefined)

	async function authorize(
		accessToken?: string,
		isInitial = false
	) {
		if (!accessToken || accessToken.length === 0) {
			if (!isInitial) {
				error.value = "No code provided."
			}
			return
		}
		const res = await opts.saveSession(accessToken)
			.catch(err => {
				error.value = err.message
				return err
			})
		if (!(res instanceof Error)) {
			await navigateTo(opts.successPath ?? rc.public.auth.authRoutes.postRegisteredLogin)
		}
	}

	async function cancel() {
		await navigateTo(opts.cancelPath ?? rc.public.auth.authRoutes.login)
	}

	return {
		authUri,
		initialAccessToken,
		manualAccessToken,
		error,
		authorize,
		cancel
	}
}
