import { defineVitestProject } from "@nuxt/test-utils/config"
import Unimport from "unimport/unplugin"
import { defineConfig } from "vitest/config"

// #awaiting https://github.com/nuxt/test-utils/issues/1490#issuecomment-3661241408
const plugins = [
	{
		name: "ignore-bun-test",
		enforce: "pre",
		resolveId(id: string) {
			if (id === "bun:test") {
				return { id: "bun:test", external: true }
			}
			return
		}
	} as any
]

/**
 * Use this for projects that don't need a DOM but need nuxt path resolution (e.g. endpoint tests).
 *
 * `defineVitestProject` hardcodes `test.environment = "nuxt"` (see @nuxt/test-utils/dist/config.mjs), which installs HappyDOM's globals even when "node" is passed. Resetting the environment to "node" instead keeps the platform-native globals, which are internally consistent, so plain `fetch` + `FormData` + `File` just work.
 */
async function defineNodeVitestProject(config: Parameters<typeof defineVitestProject>[0]) {
	const project = await defineVitestProject(config)
	project.test!.environment = "node"
	return project
}

const tags = [
	{ name: "server" }
]

export default defineConfig({
	plugins,
	test: {
		tags,
		projects: [
			// https://github.com/nuxt/test-utils/issues/531
			await defineNodeVitestProject({
				test: {
					name: "unit",
					include: ["test/unit/*.{test,spec}.ts"],
					environment: "node",
					tags
				},
				// to get around this being a node env and nuxt server imports not working
				plugins: [
					...plugins,
					// required for server imports to work
					Unimport.vite({
						dirs: ["../src/runtime/server/utils"]
					})
				]
			})
		]
	},
	server: {
		watch: {
			ignored: ["**/*.devenv*", "**/.direnv*"],
			usePolling: true,
			ignoreInitial: true,
			followSymlinks: true
		}
	}
})
