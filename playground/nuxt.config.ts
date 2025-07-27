import { genAuthSecretKeys } from "@witchcraft/nuxt-auth/build/genAuthSecretKeys"

export default defineNuxtConfig({
	ignore: [".direnv/**", ".devenv/**"],
	watchers: {
		chokidar: {
			ignoreInitial: true,
			ignored: [".direnv", ".devenv"],
		}
	},
	devtools: { enabled: true },
	hooks: {
		// https://github.com/nuxt/nuxt/issues/30481
		"nitro:config"(nitroConfig) {
			nitroConfig.devStorage ??= {}
			nitroConfig.devStorage.root = {
				driver: "fs-lite",
				readOnly: true,
				base: nitroConfig.rootDir,
			}
		}
	},
	compatibilityDate: "2024-09-23",
	future: {
		compatibilityVersion: 4 as const
	},

	runtimeConfig: {
		...genAuthSecretKeys(["google", "github"]),
		public: {
			appInfo: {
				name: "Nuxt-Auth Playground",
				subName: "A playground for the Nuxt Auth module.",
			},
		},
	},
	modules: [
		"@witchcraft/nuxt-utils",
		"@witchcraft/ui/nuxt",
		"@witchcraft/nuxt-logger",
		"@witchcraft/nuxt-postgres",
		// "@witchcraft/nuxt-auth",
		"../src/module",
	],
	postgres: {
		devAutoGenerateMigrations: true,
		additionalOptions: {
			// temp
			ssl: false
		}
	},
	auth: {
		authRoutes: {
			postRegisteredLogin: "/authed"
		},
	}
})

