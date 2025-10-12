import { navigateTo, useRuntimeConfig } from "#imports"

/**
 * Creates an external (e.g. desktop) auth handler.
 */
export function createExternalAuthHandler(
/**
 * The name of the platform.
 *
 * The `deeplink` query param will be set to this.
 *
 * The actual protocol scheme it maps to can be set in {@link createAuthHandler}.
 */
	name: string,
	/**
	 * Should return whether on this platform.
	 *
	 * e.g. isElectron()
	 */
	isExternal: () => boolean,
	/**
	 * The url of the server on which to open the auth action url.
	 *
	 * This is allowed to be undefined because it might only be available in some environments, BUT, it cannot be undefined when isExternal returns true.
	 */
	serverUrl: string | (() => string) | (() => Promise<string>) | undefined,
	/**
	 * The function on the external **platform** to open the url on a browser.
	 *
	 * This is allowed to be undefined because it might only be available in some environments, BUT, it cannot be undefined when isExternal returns true.
	 */
	open: ((url: string) => void | Promise<void>) | undefined,
	/**
	 * The callback path on the external **platform**, it will be redirected here using `navigateTo`.
	 *
	 * @default runctimeConfig().public.auth.authRoutes.deeplink
	 */
	deeplinkCallbackPath: string = useRuntimeConfig().public.auth.authRoutes.deeplink!

) {
	return async (action: "login" | "logout", url: string) => {
		if (action !== "login") return false
		if (!isExternal()) return false

		if (deeplinkCallbackPath === undefined) {
			throw new Error("createExternalAuthHandler: deeplinkCallbackPath cannot be undefined. See docs for more info.")
		}

		if (!serverUrl) throw new Error("createExternalAuthHandler: serverUrl cannot be undefined when isExternal returns true. See docs for more info.")
		if (!open) throw new Error("createExternalAuthHandler: open cannot be undefined when isExternal returns true. See docs for more info.")

		let origin = typeof serverUrl === "function" ? serverUrl() : serverUrl
		if (origin instanceof Promise) {
			origin = await origin
		}
		const serverAuth = new URL(url, origin)
		serverAuth.searchParams.set("deeplink", name)
		const serverAuthUri = encodeURIComponent(serverAuth.toString())

		const callbackUrl = new URL(deeplinkCallbackPath, window.location.origin)
		callbackUrl.searchParams.set("authUri", serverAuthUri)

		void open(serverAuth.toString())

		// bit of a dirty hack to return true before navigating
		// todo maybe we could await the returned navigation promise?
		setTimeout(() => {
			void navigateTo(callbackUrl.toString(), { external: true })
		}, 0)
		return true
	}
}
