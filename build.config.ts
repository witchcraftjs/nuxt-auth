// eslint-disable-next-line import/no-extraneous-dependencies
import { defineBuildConfig } from "unbuild"

export default defineBuildConfig({
	entries: [
		// "./src/runtime/createAuthSchema.ts",
		{
			builder: "rollup",
			input: "./src/createAuthSchema.ts",
			outDir: "./dist/",
		},
		"src/module.ts",
		{
			builder: "mkdist",
			input: "./src/runtime/",
			outDir: "./dist/runtime/",
			ext: "js",
			pattern: "**/*",
		}

	],
})
