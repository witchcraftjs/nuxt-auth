/**
 * Fails before any test starts when the server is not answering, or answers with an error.
 *
 * The probe is a real route that reads the db, so it catches a server that is up but broken
 * (a module init throw, a missing table) instead of letting every test time out on its own.
 */
export async function assertServerHealthy(baseUrl: string): Promise<void> {
	const endpoint = `${baseUrl}/api/auth/username/valid?username=${`healthprobe${Date.now()}`}`
	const response = await fetch(endpoint)
		.then(res => res)
		.catch((error: unknown) => {
			throw new Error(
				`[healthcheck] no answer from ${baseUrl}, start the app first (pnpm test:server) or check the devenv process.\n${String(error)}`
			)
		})
	const body = await response.text()
	if (!response.ok || (body !== "true" && body !== "false")) {
		throw new Error(
			`[healthcheck] ${endpoint} answered ${response.status} ${response.statusText}, expected a JSON true or false.\n${body}`
		)
	}
}
