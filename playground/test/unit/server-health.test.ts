import { describe, it } from "vitest"

import { assertServerHealthy } from "../healthcheck.js"

describe("server health", { tags: ["server"] }, () => {
	it("answers on the auth api", async () => {
		await assertServerHealthy(`http://localhost:${process.env.NUXT_PORT}/api/health`)
	})
})
