/** The port the dev server uses when `NUXT_PORT` is not set. devenv allocates it. */
const defaultPort = "3001"

/** The local certificate the devenv shell exports (file paths), undefined when it exports none. Serving https needs both. */
export const localhostCerts = process.env.LOCALHOST_KEY_PEM && process.env.LOCALHOST_PEM
	? { key: process.env.LOCALHOST_KEY_PEM, cert: process.env.LOCALHOST_PEM }
	: undefined

/** The url the local server is reached on. https when the devenv shell exported the local certificate. */
export const localhostUrl = (port = process.env.NUXT_PORT ?? defaultPort): string =>
	`${localhostCerts ? "https" : "http"}://localhost:${port}`
