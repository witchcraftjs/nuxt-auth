import { genAuthSecretKeys } from "@witchcraft/nuxt-auth/build/genAuthSecretKeys"

export default defineNuxtConfig({
	modules: [
		"@witchcraft/nuxt-utils",
		"@witchcraft/ui/nuxt",
		"@witchcraft/nuxt-postgres",
		"../src/module"
		// the below also works, just remember to run the update-dep script and uncomment ../src/module above before attempting to use the file: linked module
		// "@witchcraft/nuxt-auth",
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
		},
		allowedOrigins: [
			...(process.env.NODE_ENV !== "production" ? ["http://localhost:3000"] : []),
			"http://localhost:3000" // in a real app this would be the domain of your app
		]
	},
	postgres: {
		devAutoGenerateMigrations: true,
		connectionOptions: {
			// temp
			ssl: false
		}
	}
})
