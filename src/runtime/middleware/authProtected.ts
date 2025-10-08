import { isArray } from "@alanscodelog/utils/isArray"
import { keys } from "@alanscodelog/utils/keys"
import { pick } from "@alanscodelog/utils/pick"
import type { RouteMeta } from "vue-router"

import { defineNuxtRouteMiddleware, navigateTo, useRuntimeConfig } from "#imports"

import { useAuth } from "../composables/useAuth.js"

export default defineNuxtRouteMiddleware(async (to, from) => {
	const rc = useRuntimeConfig()
	const config = rc.public.auth
	const auth = useAuth()

	const meta: RouteMeta["auth"] = to.meta.auth ?? {}

	const isRegistered = auth.user.value?.isRegistered ?? false
	const isAuthenticated = !!auth.user.value
	// const isSemiAuthed = auth.isSemiAuthed.value

	const fallbackRedirectPath
		= isAuthenticated && isRegistered
			? auth.authRoutes.postRegisteredLogin
			: isAuthenticated && !isRegistered
				? auth.authRoutes.register
				: auth.authRoutes.login

	const query = typeof from.query === "object" && meta.keepQuery
		? isArray(meta.keepQuery)
			? pick(from.query as any, meta.keepQuery)
			: from.query as any
		: {}

	if (typeof meta.redirectTo === "function") {
		// so function can use magic paths
		meta.redirectTo = meta.redirectTo()
	}

	const redirectTo
		= (!meta.redirectTo
			? fallbackRedirectPath
			: meta.redirectTo === "$login"
				? auth.authRoutes.login
				: meta.redirectTo === "$register"
					? auth.authRoutes.register
					: meta.redirectTo === "$postRegisteredLogin"
						? auth.authRoutes.postRegisteredLogin
						: meta.redirectTo === "$externalCode"
							? auth.authRoutes.externalCode
							: meta.redirectTo && keys(config.additionalMiddlewarePaths ?? []).includes(meta.redirectTo)
								? config.additionalMiddlewarePaths[meta.redirectTo]
								: meta.redirectTo)
							+ (keys(query).length > 0
								? `?${new URLSearchParams(query).toString()}`
								: ""
							)

	const matchesCondition
		= typeof meta.only === "function"
			? meta.only(auth)
			: !meta.only && !isAuthenticated && isRegistered
					? true
					: (meta.only === "authenticated" && isAuthenticated)
						|| (meta.only === "authenticated-registered" && isAuthenticated && isRegistered)
						|| (meta.only === "registered" && isRegistered)
						|| (meta.only === "authenticated-unregistered" && isAuthenticated && !isRegistered)
						|| (meta.only === "unauthenticated" && !isAuthenticated)

	const doRedirect = !matchesCondition && to.path !== redirectTo

	if (import.meta.client && import.meta.dev) {
		// eslint-disable-next-line no-console
		console.log({
			ns: "auth:middleware:authProtected",
			willRedirect: doRedirect,
			isRegistered,
			isAuthenticated,
			meta,
			matchesCondition,
			redirectTo
		})
	}

	if (doRedirect) {
		if (meta.handleRedirect) {
			return meta.handleRedirect(redirectTo)
		} else {
			return navigateTo(redirectTo)
		}
	}
})
