import { vueConfig } from "@alanscodelog/eslint-config"
import { createConfigForNuxt } from "@nuxt/eslint-config/flat"

// Run `npx @eslint/config-inspector` to inspect the resolved config interactively
export default createConfigForNuxt({
	features: {
		tooling: false, // is overriding standalone?
		stylistic: false,
		standalone: false
	},
	dirs: {
		src: [
			"./playground",
		],
	},
})
	.append(
		//@ts-expect-error https://github.com/nuxt/eslint/issues/497
		...vueConfig,
		{
			ignores: [".nuxt/"],
			// for auto imports
			rules: {
				"no-undef": "off",
			}
		}
	)
