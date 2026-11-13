import { sql } from "drizzle-orm"

import { postgres as db } from "#postgres"

/**
 * Readiness probe for CI and test setups. In dev, touches the db so it only answers once the server is fully booted, migrations included.
 *
 * See {@link https://github.com/nuxt/nuxt/issues/29771}
 */
export default defineEventHandler(async () => {
	if (import.meta.dev) {
		await db.execute(sql`SELECT 1`)
	}
	return { ok: true }
})
