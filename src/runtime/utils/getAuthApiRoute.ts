import { keys } from "@alanscodelog/utils/keys.js"
import type { PublicRuntimeConfig } from "@nuxt/schema"

import type { ApiRoutesParams } from "../../module.js"

export function getAuthApiRoute<
	T extends keyof PublicRuntimeConfig["auth"]["authApiRoutes"],
	TParams extends T extends keyof ApiRoutesParams ? ApiRoutesParams[T] : never
>(
	route: T,
	params?: TParams,
	rc?: PublicRuntimeConfig,
	queryParams?: Record<string, any>
): string {
	// electron needs to be able to import this file
	// it provides it's own runtime config so that useRuntimeConfig is never called
	// @ts-expect-error this should work fine in nuxt without the import from #imports
	rc ??= useRuntimeConfig().public
	const routes = rc.auth.authApiRoutes
	let finalRoute: string = routes[route]
	if (!finalRoute) throw new Error(`Invalid route: ${route as any}`)
	if (params) {
		for (const key of keys(params as Record<string, any>)) {
			finalRoute = finalRoute.replace(`:${key}`, (params as any)[key])
		}
	}
	if (route === "base") return finalRoute
	const query = queryParams ? `?${new URLSearchParams(queryParams).toString()}` : ""
	return `${routes.base}${finalRoute}${query}`
}
