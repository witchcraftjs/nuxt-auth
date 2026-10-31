import type { ElectronClientOptions, ExposedBridges } from "@better-auth/electron/client"

export type ElectronUserEntry = {
	directory: string
	/** Absent until the user registers, the id is what identifies them. */
	username?: string
	isLocal: boolean
	id: string
}

export type ElectronAuthApi = {
	auth: {
		exchangeSession: () => Promise<void>
		/** Test only stand-in for better-auth's `requestAuth`, so the mock login can carry an identity. */
		mockRequestAuth: (options: { username?: string, id?: string, provider?: string, devBypassRegistration?: boolean }) => Promise<void>
		/**
		 * better-auth's own bridges. It puts each of them straight on `window`, ugly, so we put the 2 we actually use under a nice name space.
		 */
		betterAuth: Pick<ExposedBridges<ElectronClientOptions>, "authenticate" | "requestAuth">
	}
}

/**
 * What we expect to find at `window.electron.api`: our own auth bridges plus the app's user registry, which the app implements and exposes.
 *
 * Temporary, until `@witchcraft/nuxt-electron` implements plugins and exports its types.
 */
export type ExpectedElectronApi = ElectronAuthApi & {
	users: {
		/** Every stored user, local and external. Dir names carry the kind, `<id>` or `local-<id>`. */
		list: () => Promise<ElectronUserEntry[]>
		create: (options: { id: string, username: string }) => Promise<void>
		update: (options: { id: string, patch: { username?: string, name?: string, image?: string } }) => Promise<void>
		delete: (id: string) => Promise<void>
		/** Persists the user as the active one and reopens the window in that user's partition. */
		switchUserAndSoftReload: (id: string | undefined) => Promise<void>
	}
}


/** Test-only bridge, preload invokes what main handles. */
export const mockRequestAuthChannel = "auth:mockRequestAuth"

/** Session exchange bridge, preload invokes what main handles. */
export const exchangeSessionChannel = "auth.exchangeSession"
