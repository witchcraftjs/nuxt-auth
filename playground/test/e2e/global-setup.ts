import { assertServerHealthy } from "../healthcheck.js"

/** Runs once before the Playwright projects, both of which need the server up. */
export default async function globalSetup(): Promise<void> {
	const port = process.env.NUXT_PORT
	if (!port) throw new Error("[healthcheck] NUXT_PORT is not set, run the tests through their pnpm scripts.")
	await assertServerHealthy(`http://localhost:${port}/api/health`)
}
