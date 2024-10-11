// careful with imports, esm is borked, see nuxt-postgres/src/drizzleConfig.ts
import { drizzleConfig } from "@witchcraft/nuxt-postgres/drizzleConfig.js"
import { defineConfig } from "drizzle-kit"
import path from "path"


export default defineConfig({
	...drizzleConfig,
	schema: path.resolve("db/schema.ts"),
	out: "./db/migrations",
})

