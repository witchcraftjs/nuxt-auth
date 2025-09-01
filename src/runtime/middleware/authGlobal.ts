import { jsonSafeParse } from "@alanscodelog/utils/jsonSafeParse"

import {
	defineNuxtRouteMiddleware,
	useFetch,
	useRuntimeConfig,
	useState,
} from "#imports"

import { getAuthApiRoute } from "../utils/getAuthApiRoute.js"

export default defineNuxtRouteMiddleware(async (_to, _from) => {
	const doFetch = useState("auth:_fetch",() => true)
	const userData = useState("auth:user",() => null)
	const semiAuthed = useState("auth:semiAuthed",() => false)

	if (import.meta.client && import.meta.dev) {
		// this used to work without issues in nuxt ~3.14, not sure what happened
		// logger appears empty, composable looses initialized state, useServerLogger doesn't work either
		// const logger = useLogger()
		// now does not even work on the client (can't find pino???)
		// eslint-disable-next-line no-console
		console.log({ ns: "auth:middleware:authGlobal", doFetch: doFetch.value, userData: userData.value })
	}

	if (!doFetch.value) return
	const res = await useFetch<any>(getAuthApiRoute(useRuntimeConfig().public,"usersInfo"))
	doFetch.value = false
	userData.value = res.data.value
	if (import.meta.client && !userData.value) {
		const user = jsonSafeParse(localStorage.getItem("auth:user") ?? "null")
		if (user.isOk && user.value) {
			semiAuthed.value = true
			userData.value = user.value as any
		}
	}

	if (import.meta.client && import.meta.dev) {
		// const logger = useLogger()
		// eslint-disable-next-line no-console
		console.log({
			ns: "auth:middleware:authGlobal:fetched",
			userData: userData.value,
			semiAuthed: semiAuthed.value,
		})
	}
})
