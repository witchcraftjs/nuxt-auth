import { genAuthSecretKeys } from "../src/runtime/build/genAuthSecretKeys.js"

export default defineNuxtConfig({
	modules: [
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
			}
		}
	},
	ignore: [".direnv/**", ".devenv/**"],
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
	hooks: {
		// https://github.com/nuxt/nuxt/issues/30481
		"nitro:config"(nitroConfig) {
			nitroConfig.devStorage ??= {}
			nitroConfig.devStorage.root = {
				driver: "fs-lite",
				readOnly: true,
				base: nitroConfig.rootDir
			}
		}
	},
	auth: {
		authRoutes: {
			postRegisteredLogin: "/authed"
		}
	},
	postgres: {
		devAutoGenerateMigrations: true,
		serverPostgresjsOptions: {
			// temp
			ssl: false
		}
	}
})
