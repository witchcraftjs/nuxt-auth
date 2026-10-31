// careful with imports, esm is borked, see nuxt-postgres/src/drizzleConfig.ts
import { drizzleConfig } from "@witchcraft/nuxt-postgres/drizzleConfig"
import { defineConfig } from "drizzle-kit"

export default defineConfig({
	...drizzleConfig,
	schema: "db/schema.ts"
})

