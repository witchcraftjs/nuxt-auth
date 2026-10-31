import type { ExpectedElectronApi } from "@witchcraft/nuxt-auth/electron/preload"
import type { ElectronLoggerApi } from "@witchcraft/nuxt-logger/electron/preload"

/**
 * Everything the playground's preload puts on `window`. The app gets it through the global
 * declaration below, and code that runs outside the app's project, such as the electron
 * tests, can cast with it.
 */
export type PlaygroundWindow = Window & {
	electron: {
		api: ElectronLoggerApi & ExpectedElectronApi & {
			open: (url: string) => Promise<void>
		}
		meta: {
			env: {
				LOG_LEVEL: string | undefined
				LOG_WRITE_LEVEL: string | undefined
			}
		}
	}
}

declare global {
	interface Window {
		electron: PlaygroundWindow["electron"]
		authenticate: PlaygroundWindow["authenticate"]
		requestAuth: PlaygroundWindow["requestAuth"]
		/** Set by the preload in a test run, see `app-electron/preload.ts`. */
		// eslint-disable-next-line @typescript-eslint/naming-convention
		__IS_TEST?: boolean
	}
}
