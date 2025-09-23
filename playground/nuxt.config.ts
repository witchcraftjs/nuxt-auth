import { genAuthSecretKeys } from "@witchcraft/nuxt-auth/build/genAuthSecretKeys"
import { fileURLToPath } from "node:url"

export default defineNuxtConfig({
	modules: [
		"@witchcraft/nuxt-utils",
		"@witchcraft/ui/nuxt",
		"@witchcraft/nuxt-postgres",
		"@witchcraft/nuxt-logger",
		// this won't work for local dev because both the app and the module will be using the ui library
		// and it uses symbols for value injection and because they're using the library
		// from different node_modules, it will fail
		// "../src/module"
		// this works, just remember to run the update-dep script and uncomment ../src/module above before attempting to use the file: linked module
		"@witchcraft/nuxt-auth"
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
