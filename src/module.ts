import { crop } from "@alanscodelog/utils/crop.js"
import { addComponentsDir, addImportsDir, addRouteMiddleware, addServerImports, addServerImportsDir, addServerScanDir, addTemplate, createResolver, defineNuxtModule, installModule, useLogger } from "@nuxt/kit"
import { type CookieSerializeOptions } from "cookie-es"
import { defu } from "defu"

import type { AdditionalApiRoutes, ProviderNames, Secrets, SessionCookieOptions } from "./runtime/types"
export type * from "./runtime/types"
export type * from "./createAuthSchema.js"
import type { NuxtPage } from "@nuxt/schema"

import { type useAuth } from "./runtime/composables/useAuth.js"

declare global {
}
declare module "vue-router" {
	interface RouteMeta {
		auth?: {
			keepQuery?: boolean | string[]
			/**
			 * Only allow users on the page that match the given conditions.
			 */
			only?: "authenticated" | "authenticated-registered" | "registered" | "authenticated-unregistered" | "unauthenticated" | ((auth: ReturnType<typeof useAuth>) => boolean)

			/** Path to redirect to. Can be a magic path like "$login" or "$register". */
			redirectTo?: string | "$login" | "$register" | "$postRegisteredLogin" | "$externalCode" | (() => string)
			handleRedirect?: (url: string) => void | Promise<void>
		}
	}
}

declare module "@nuxt/schema" {
	interface RuntimeConfig extends Secrets {
		authSecret: string
	}
	interface PublicRuntimeConfig {
		auth: Required<Omit<
			ModuleOptions,
			| "useGlobalMiddleware"
			| "authRoutes"
			| "authApiRoutes"
		>> & {
			authRoutes: Required<ModuleOptions["authRoutes"]>
			authApiRoutes: Required<ModuleOptions["authApiRoutes"]>
			isSecure: boolean
		}
	}
}


export interface ModuleOptions {
	enabledProviders: ProviderNames[]
	useGlobalMiddleware: boolean
	onlySaveUnregisteredUserAccountInfo: boolean
	/**
	 * Options for the provider cookies.
	 *
	 * `secure` is not included in the options because it's determined by whether `useRuntimeConfig().public.auth.isSecure` was defined (which this module sets automatically).
	 *
	 * @default {
	 * 	maxAge: 60 * 10, // 10 minutes
	 * 	sameSite: "lax" as const,
	 * 	httpOnly: true,
	 * 	path: "/",
	 * }
	 */
	providerCookieOpts: Omit<Partial<CookieSerializeOptions>, "secure">
	/**
	 * The number of milliseconds the session cookie expires after.
	 *
	 * Can also be overriden when creating the `SessionManager`.
	 *
	 * @default 1000 * 60 * 60 * 24 * 30 // 30 days
	 */
	sessionExpiresAt: number
	/**
	 *
	 * Options for the session cookie.
	 *
	 * Can also be overriden when creating the `SessionManager`.
	 *
	 * `secure` is not included in the options because it's determined by whether `useRuntimeConfig().public.auth.isSecure` was defined (which this module sets automatically).
	 *
	 * @default {
	 * 	sameSite: "lax" as const,
	 * 	httpOnly: true,
	 * 	path: "/",
	 * }
	 */
	sessionCookieOpts: Omit<SessionCookieOptions, "maxAge" | "secure" | "expiresAt">
	authRoutes: Partial<{
		/**
		 * When the user tries to go to a protected route, they will be redirected here.
		 *
		 * @default "/"
		 */
		unauthenticated: string
		/**
		 * The route for the login page.
		 *
		 * @default "/auth/login"
		 *
		 * The path is also used to redirect unauthenticated users in the protected routes.
		 */
		login: string
		/**
		 *
		 * For redirecting the user after login if they aren't registered yet.
		 *
		 * @default "/auth/register"
		 *
		 * Also used to redirect un-registered authenticated users in the protected routes.
		 */
		register: string
		/**
		 * After a registered user finishes registration, or when an existing user logs in, they will be redirected here.
		 *
		 * @default "/"
		 */
		postRegisteredLogin: string
		/**
		 * The route to redirect to once a user has been authenticated and registered when the deeplink query param is passed.
		 *
		 * See the External Auth Handlers section of the README for more info.
		 *
		 * @default "/auth/code"
		 */
		externalCode: string
		/**
		 * The url to open from `/auth/code`. It is appended to the deeplink scheme (see {@link Auth.deepLinkSchemes}) and the accessToken will be appended to it.
		 *
		 * How opening it is handled is up to the app, but the idea is it's a single page that can handle receiving the code via a query param or manually (a component, `AuthExternalCallback` is provided for this purpose).
		 *
		 * @default `/auth/external/callback`
		 */
		deeplink: string
		/**
		 * The route that handles mocking the OAuth flow for development purposes.
		 *
		 * @default `/auth/mock`
		 */
		mockAuth: string
	}>
	/**
	 * The routes for the api calls.
	 *
	 * If you stick to using these as variables from the runtime config, you can change them so long as you don't rename the dynamic parts:
	 *
	 * ```ts
	 * fetch(`${useRuntimeConfig().public.auth.authApiRoutes.usersInfo}`)
	 * ```
	 */
	authApiRoutes: Partial<{
		/** @default "/api/auth" */
		base: string
		/** @default "/users/info" */
		usersInfo: string
		/** @default "/external/exchange" */
		externalExchange: string
		/** @default "/users/:id/accounts" */
		usersIdAccounts: string
		/** @default "/logout" */
		logout: string
		/** @default "/login/:provider" */
		login: string
		/** @default "/register" */
		register: string
		/** @default "/callback/:provider" */
		callback: string
		/**
			* Note the route is NOT defined by the module, you must extend the routes and define it yourself if you are using the UserRegistration component which makes use of it.
			*
			* @default "/api/auth/public/users/:username/valid"
			*/
		usernameValid: string
	}> & Partial<AdditionalApiRoutes>
	/** Additional "magic" paths that can be used for the `auth.redirectTo` page meta property when using the `authProtected` middleware. */
	additionalMiddlewarePaths?: Record<string, string>
}
export default defineNuxtModule<ModuleOptions>({
	meta: {
		name: "auth",
		configKey: "auth",
	},
	defaults: {
		useGlobalMiddleware: true,
		providerCookieOpts: {
			httpOnly: true,
			path: "/",
			maxAge: 60 * 10, // 10 minutes
			sameSite: "lax" as const
		},
		sessionExpiresAt: 1000 * 60 * 60 * 24 * 30,
		sessionCookieOpts: {
			sameSite: "lax" as const,
			httpOnly: true,
			path: "/",
		},
		enabledProviders: [
			"google",
			"github",
		] as ProviderNames[],
		authRoutes: {
			login: "/auth/login",
			register: "/auth/register",
			unauthenticated: "/",
			postRegisteredLogin: "/",
			externalCode: "/auth/code",
			deeplink: "/auth/external/callback",
			mockAuth: "/auth/mock",
		},
		authApiRoutes: {
			base: "/api/auth",
			usersInfo: "/users/info",
			externalExchange: "/external/exchange",
			usersIdAccounts: "/users/:id/accounts",
			logout: "/logout",
			login: "/login/:provider",
			callback: "/callback/:provider",
			register: "/register",
			usernameValid: "/public/users/:username/valid",
		} satisfies Required<ModuleOptions["authApiRoutes"]> as any,
		onlySaveUnregisteredUserAccountInfo: false,
		additionalMiddlewarePaths: {},
	} satisfies Required<ModuleOptions>,
	async setup(options, nuxt) {
		const moduleName = "@witchcraft/nuxt-auth"
		const logger = useLogger(moduleName)
		await installModule("@witchcraft/nuxt-logger", (nuxt.options as any).logger)
		// await installModule("@witchcraft/nuxt-postgres", (nuxt.options as any).postgres)

		const { resolve } = createResolver(import.meta.url)
		addComponentsDir({
			path: resolve("runtime/components"),
			prefix: "Auth",
			global: true,
		})
		if (!nuxt.options.runtimeConfig.authSecret) {
			logger.error("Missing authSecret in runtimeConfig.")
		}
		if (nuxt.options.runtimeConfig.authSecret?.length === 0) {
			logger.warn("authSecret is empty. This is not recommended.")
		}
		nuxt.options.runtimeConfig.public.auth = defu(
			nuxt.options.runtimeConfig.public.auth as any,
			{
				isSecure: (!!nuxt.options.devServer.https || process.env.mode === "production")
			},
			options,
		)
		delete (nuxt.options.runtimeConfig.public.auth as any).useGlobalMiddleware

		nuxt.options.alias["#auth"] = resolve("runtime")

		addImportsDir(resolve("runtime/composables"))
		addImportsDir(resolve("runtime/utils"))
		addServerScanDir(resolve("runtime/server"))
		addServerImportsDir(resolve("runtime/server/utils"))
		addServerImports([
			{
				name: "getAuthApiRoute",
				from: resolve("runtime/utils/getAuthApiRoute"),
			}
		])
		for (const file of [
			// "runtime",
			"runtime/types", // why, if not transpiled import path is wrong :/
			"runtime/server/utils/Auth",
			"runtime/server/helpers/getSafeSecretsInfo",
			"runtime/server/helpers/logSafeRoute",
			"runtime/server/utils/createAuthHandler",
			"runtime/server/utils/createAuthMiddleware",
			"runtime/utils/getAuthApiRoute",
			"runtime/core/providers/google",
			"runtime/core/providers/github",
			"runtime/utils/createExternalAuthHandler",
			// careful, no need to add createAuthSchema as that needs to be importable as is by drizzle via a regular import
		]) {
			nuxt.options.build.transpile.push(resolve(file))
		}

		await installModule("@witchcraft/ui/nuxt", (nuxt.options as any).witchcraftUi)
		await installModule("unplugin-icons/nuxt")

		addTemplate({
			filename: "witchcraft-nuxt-auth.css",
			write: true,
			getContents: () => crop`
				@source "${resolve("runtime/components")}";
			`
		})

		const mockAuth = nuxt.options.runtimeConfig.public.auth.authRoutes.mockAuth
		if (process.env.NODE_ENV !== "development" && mockAuth) {
			nuxt.hook("pages:extend", (pages: NuxtPage[]) => {
				const i = pages.findIndex(page => page.path === mockAuth)
				pages.splice(i, 1)
			})
		}

		addRouteMiddleware({
			name: "authProtected",
			path: resolve("runtime/middleware/authProtected"),
			global: false,
		})
		addRouteMiddleware({
			name: "authGlobal",
			path: resolve("runtime/middleware/authGlobal"),
			global: options.useGlobalMiddleware,
		})
	},
})

