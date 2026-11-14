import { localhostUrl } from "../localhostUrl.js"

/**
 * Fails before any test starts when the server is not answering, or answers with an error.
 */
export async function assertServerHealthy(path = "/api/health"): Promise<void> {
	const endpoint = `${localhostUrl()}${path}`
	const response = await fetch(endpoint)
		.then(res => res)
		.catch((error: unknown) => {
			throw new Error(
				`[healthcheck] no answer from ${endpoint}, start the app first (pnpm test:server) or check the devenv process.\n${String(error)}`
			)
		})
	const headers = Object.fromEntries(response.headers.entries())
	const body = await response.json().catch(() => null)
	if (!response.ok || body?.ok !== true) {
		throw new Error(
			`[healthcheck] ${endpoint} answered ${response.status} ${response.statusText}, expected a JSON { ok: true }.\nheaders: ${JSON.stringify(headers)}\nbody: ${JSON.stringify(body)}`
		)
	}
}
