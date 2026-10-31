import { genAuthSecretKeys } from "../src/runtime/build/genAuthSecretKeys.js"

// the server the app talks to, baked at build time. it is always the local server here but a real app would return its own site url instead, usually gated on an environment variable for production builds
const publicServerUrl = `http://localhost:${process.env.NUXT_PORT ?? 3001}`

export default defineNuxtConfig({
	modules: [
		"@witchcraft/nuxt-electron",
		"@witchcraft/nuxt-utils",
		"@witchcraft/ui/nuxt",
		"@witchcraft/nuxt-postgres",
		"@witchcraft/nuxt-logger",
		"../src/module"
	],
	devtools: { enabled: true },
	runtimeConfig: {
		...genAuthSecretKeys(["google", "github"]),
		public: {
			appInfo: {
				name: "Nuxt-Auth Playground",
				subName: "A playground for the Nuxt Auth module."
			},
			auth: {
				// the window is served from the app scheme, the auth client needs the
				// server origin (see useAuth)
				publicServerUrl
			}
		}
	},
	ignore: [".devenv/**"],
	routeRules: {
		...(process.env.BUILD_ELECTRON
			// required for auth to work on electron, they are also pre-rendered as the nuxt-electron module forces them to be since we included them below
			? {
					"/auth/login": { ssr: false },
					"/auth/external/callback": { ssr: false }
				}
			: {})
	},
	watchers: {
		chokidar: {
			ignoreInitial: true,
			ignored: [".direnv", ".devenv"]
		}
	},
	future: {
		compatibilityVersion: 4 as const
	},
	compatibilityDate: "2024-09-23",
	// for nuxt-electron, otherwise not needed
	nitro: {
		output: {
			dir: ".dist/web/.output",
			serverDir: ".dist/web/.output/server",
			publicDir: ".dist/web/.output/public"
		}
	},
	vite: {
		server: {
			watch: {
				usePolling: true
			}
		}
	},
	typescript: {
		tsConfig: {
			include: ["../app-electron/**/*.ts", "../preload-types.d.ts"]
		}
	},
	hooks: {
		// https://github.com/nuxt/nuxt/issues/30481
		["nitro:config"]: nitroConfig => {
			nitroConfig.devStorage ??= {}
			nitroConfig.devStorage.root = {
				driver: "fs-lite",
				readOnly: true,
				base: nitroConfig.rootDir
			}
		}
	},
	auth: {
		devBypassAuth: true,
		authRoutes: {
			postRegisteredLogin: "/authed"
		},
		deeplinkSchemes: {
			electron: "playground-electron"
		}
	},
	electron: {
		// the app's entry route, always included and prerendered
		electronRoute: "/",
		// the allow-list of pages that ship in the app, everything else is removed from the electron build.
		// browser only pages do not belong here, app should redirect to opening a web page
		// everything here gets pre-rendered during the electron build ALWAYS
		additionalRoutes: [
			// required
			"/auth/login",
			"/auth/external/callback",
			// a dynamic route like this can be pre-rendered. It will just run only client side.
			"/users/:username",
			// you should also add any authed only pages you need users to access from the app
			// remember to disable ssr for them or set `disableServerRedirect: true` on the middleware
			// typically what is done is you have something like /app which can run anywhere client side, and any browser specific stuff on other routes
			"/authed"
		],
		additionalElectronVariables: {
			// nuxi build always sets NODE_ENV=production, so the production build
			// has to be marked explicitly or every build looks like production
			bakedIsProduction: process.env.PRODUCTION_BUILD === "true" ? `"true"` : `"false"`,
			// an app bakes its real site url here
			publicServerUrl: `"${publicServerUrl}"`
		}
	},
	postgres: {
		usePgLiteOnServer: true,
		devAutoGenerateMigrations: true
		// ignore, was needed only when running the full postgres instance (we now rely on pglite for testing)
		// serverPostgresjsOptions: {
		// 	ssl: false
		// }
	}
})
