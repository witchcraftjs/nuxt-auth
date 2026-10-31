import {
	nuxtModuleAppends,
	nuxtModuleConfig
} from "@alanscodelog/eslint-config"
import { createConfigForNuxt } from "@nuxt/eslint-config"
// Run `npx @eslint/config-inspector` to inspect the resolved config interactively
export default createConfigForNuxt({
	...nuxtModuleConfig
})
	.append([
		...nuxtModuleAppends,
		{
			rules: {
				"jsdoc/check-tag-names": ["warn", { definedTags: [
				] }]
			}
		},
		{
			files: ["playground/app-electron/**/*.ts"],
			rules: {
				// the nearest package.json is electron-builder's second one, which only lists what gets packaged
				"import/no-extraneous-dependencies": ["warn", {
					devDependencies: ["!src/**/*"],
					optionalDependencies: true,
					peerDependencies: true,
					packageDir: "./playground"
				}]
			}
		}
	])
