import { crop } from "@alanscodelog/utils/crop"
import {
	addComponentsDir,
	addImportsDir,
	addRouteMiddleware,
	addServerImportsDir,
	addServerScanDir,
	addTemplate,
	createResolver,
	defineNuxtModule,
	useLogger
} from "@nuxt/kit"
import type { CookieSerializeOptions } from "cookie-es"
import { defu } from "defu"

import type { SessionCookieOptions } from "./runtime/types"


export type * from "./runtime/types"
export type * from "./runtime/server/utils/createAuthSchema.js"
import type { NuxtPage } from "@nuxt/schema"

import type { useAuth } from "./runtime/composables/useAuth.js"

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

			/**
			 * Do not redirect during the server render. The page is rendered and the redirect is decided in the browser instead.
			 *
			 * Use it on pages a local user must be able to reach: a local user exists only in that window's storage, so the server cannot see them and would send them to `authRoutes.unauthenticated`.
			 */
			disableServerRedirect?: boolean
			/** Path to redirect to. Can be a magic path like "$login" or "$register". */
			redirectTo?: string | "$login" | "$register" | "$postRegisteredLogin" | "$externalCode" | (() => string)
			handleRedirect?: (url: string) => void | Promise<void>
		}
	}
}

export interface ModuleOptions {
	enabledProviders: string[]
	/**
	 * Deep-link schemes by name. The `electron` entry feeds the web
	 * client proxy plugin, the better-auth electron plugin, and the
	 * dev-mock deeplink redirects. No trailing colon,
	 * `myapp:` throws.
	 *
	 * @default {}
	 */
	deeplinkSchemes: { electron?: string } & Record<string, string>
	/**
	 * Enables the mock sign-in: the `devMock` server plugin, the mock page and, in a test
	 * run, electron's local short circuit.
	 *
	 * This is a public option, so every client can read it, which is harmless. The server
	 * only registers the plugin when this is on and the module runs in dev, and the plugin
	 * is tree-shaken out of production builds, so turning it on in production does nothing.
	 *
	 * @default false
	 */
	devBypassAuth: boolean
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
	 * `secure` and `httpOnly` are not configurable. `secure` is determined by better-auth. `httpOnly` is always on.
	 *
	 * `domain` is not configurable. Use better-auth's `crossSubDomainCookies` if you need cross-subdomain cookies.
	 *
	 * @default {
	 * 	sameSite: "lax" as const,
	 * 	path: "/",
	 * }
	 */
	sessionCookieOpts: Omit<SessionCookieOptions, "maxAge" | "secure" | "expires">
	/**
	 * Prefix for better-auth cookies, e.g. the session cookie is `${cookiePrefix}.session_token`.
	 *
	 * Wired to the server session cookies and `ElectronAuth`.
	 *
	 * @default "better-auth"
	 */
	cookiePrefix: string
	authRoutes: Partial<{
		/**
		 * When the user tries to go to a protected route, they will be redirected here.
		 *
		 * Also where logging out, or deleting the active user, sends the window.
		 *
		 * @default "/"
		 */
		unauthenticated: string
		/**
		 * The route for the login page.
		 *
		 * @default "/auth/login"
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
	 * The base path the catch all api is defined at (e.g. where the `[...]` server event handler is.
	 *
	 * @default "/api/auth"
	 */
	authApiRouteBase?: string
	/** Additional "magic" paths that can be used for the `auth.redirectTo` page meta property when using the `authProtected` middleware. */
	additionalMiddlewarePaths?: Record<string, string>
	/**
	 * Origin of the auth server (e.g. https://mysite.com). You can also do the dev gating here to point to your dev server or you can do it only in createBetterAuth, depends on your needs.
	 *
	 * For example, this module does it at the nuxt config level. This is because we build and bake it, dev port included into electron for testing, as it's otherwise a different pain to setup envs to override it just during testing. In a simpler app without electron it won't matter. In a more complex app, the pain might be justified to avoid rebuilds before tests.
	 *
	 * It exists because:
	 * - Electron needs it to know where the server is so it can proxy the window's requests to it.
	 * - `createBetterAuth` also uses it as better-auth's base url and trusted origin if nothing is set to override it.
	 *
	 * Required, the module throws when it is blank.
	 *
	 * @default ""
	 */
	publicServerUrl: string
}
export interface ModulePublicRuntimeConfig {
	auth: Required<Omit<
		ModuleOptions,
		| "authRoutes"
		| "deeplinkSchemes"
	>> & {
		deeplinkSchemes: ModuleOptions["deeplinkSchemes"]
		authRoutes: Required<ModuleOptions>["authRoutes"]
		isSecure: boolean
	}
}

type Secrets = Partial<
	Record<`auth${Capitalize<string>}ClientId`, string>
	& Record<`auth${Capitalize<string>}ClientSecret`, string>
>

export interface ModulePrivateRuntimeConfig extends Secrets {
	authSecret: string
}

export interface ModuleRuntimeConfig extends ModulePrivateRuntimeConfig {
	public: ModulePublicRuntimeConfig
}

declare module "@nuxt/schema" {
	interface RuntimeConfig extends ModulePrivateRuntimeConfig {}
	interface PublicRuntimeConfig extends ModulePublicRuntimeConfig {}
}

export default defineNuxtModule<ModuleOptions>({
	meta: {
		name: "auth",
		configKey: "auth"
	},
	defaults: {
		devBypassAuth: false,
		providerCookieOpts: {
			httpOnly: true,
			path: "/",
			maxAge: 60 * 10, // 10 minutes
			sameSite: "lax" as const
		},
		sessionExpiresAt: 1000 * 60 * 60 * 24 * 30,
		sessionCookieOpts: {
			sameSite: "lax" as const,
			path: "/"
		},
		cookiePrefix: "better-auth",
		enabledProviders: [
			"google",
			"github"
		],
		deeplinkSchemes: {},
		authRoutes: {
			login: "/auth/login",
			register: "/auth/register",
			unauthenticated: "/",
			postRegisteredLogin: "/",
			externalCode: "/auth/code",
			deeplink: "/auth/external/callback",
			mockAuth: "/auth/mock"
		},
		authApiRouteBase: "/api/auth",
		additionalMiddlewarePaths: {},
		publicServerUrl: ""
	} satisfies Required<ModuleOptions>,
	moduleDependencies: {
		"@witchcraft/ui": {
			version: "^0.5.0",
			optional: true
		},
		"nuxt-security": {
			version: "^2.4.0",
			optional: true
		}
	},
	async setup(options, nuxt) {
		const moduleName = "@witchcraft/nuxt-auth"
		const logger = useLogger(moduleName)

		for (const [name, scheme] of Object.entries(options.deeplinkSchemes ?? {})) {
			if (scheme.endsWith(":")) {
				throw new Error(`[${moduleName}] deeplinkSchemes.${name} must not end with a colon, got "${scheme}".`)
			}
		}

		const { resolve } = createResolver(import.meta.url)
		addComponentsDir({
			path: resolve("runtime/components"),
			prefix: "Auth",
			global: true
		})

		if (process.env.NODE_ENV !== "production"
			&& (
				!process.env.NUXT_AUTH_SECRET
				|| (process.env.NUXT_AUTH_SECRET && process.env.NUXT_AUTH_SECRET.length === 0)
			)
		) {
			logger.warn("$NUXT_AUTH_SECRET is missing or empty. This is not recommended.")
		}
		nuxt.options.runtimeConfig.public.auth = defu(
			nuxt.options.runtimeConfig.public.auth as any,
			{
				isSecure: (!!nuxt.options.devServer.https || !nuxt.options.dev || process.env.mode === "production")
			},
			options
		)
		// a prepare run loads no app config, so nothing could have set this
		if (!nuxt.options._prepare && !nuxt.options.runtimeConfig.public.auth.publicServerUrl) {
			throw new Error(`[${moduleName}] publicServerUrl is required, e.g. "http://localhost:3001". The window's session cookie is stored against its origin.`)
		}

		nuxt.options.alias["#witchcraft-nuxt-auth"] = resolve("runtime")

		addImportsDir(resolve("runtime/composables"))
		addImportsDir(resolve("runtime/utils"))
		addServerScanDir(resolve("runtime/server"))
		addServerImportsDir(resolve("runtime/server/utils"))
		for (const file of [
			// "runtime",
			"runtime/types", // why, if not transpiled import path is wrong :/
			"runtime/server/utils/assertEventWithAuthorizedUser",
			"runtime/server/utils/getBetterAuthInstance",
			"runtime/server/utils/createAuthMiddleware",
			"runtime/server/utils/createAuthSchema",
			"runtime/server/utils/createBetterAuth"
		]) {
			nuxt.options.build.transpile.push(resolve(file))
		}

		addTemplate({
			filename: "witchcraft-nuxt-auth.css",
			write: true,
			getContents: () => crop`
				@source "${resolve("runtime/components")}";
			`
		})

		const mockAuth = nuxt.options.runtimeConfig.public.auth.authRoutes.mockAuth
		// server double check as well
		const mockEnabled = options.devBypassAuth && nuxt.options.dev
		if (!mockEnabled && mockAuth) {
			nuxt.hook("pages:extend", (pages: NuxtPage[]) => {
				const i = pages.findIndex(page => page.path === mockAuth)
				if (i > -1) {
					pages.splice(i, 1)
				}
			})
		}

		addRouteMiddleware({
			name: "authProtected",
			path: resolve("runtime/middleware/authProtected"),
			global: false
		})
		addRouteMiddleware({
			name: "authGlobal",
			path: resolve("runtime/middleware/authGlobal"),
			global: true
		})
	}
})
