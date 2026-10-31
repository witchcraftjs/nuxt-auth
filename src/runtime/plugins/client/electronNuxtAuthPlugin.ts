import { navigateTo, useRuntimeConfig, useState } from "#app"

import type { ElectronUserEntry, ExpectedElectronApi } from "../../electron/types.js"
import type { AuthUser } from "../../types.js"
import { userStorageKey } from "../../types.js"

/**
 *{@link ExternalPlugin} for the renderer side of electron. useAuth will divert methods to it as needed when the plugin reports it is on electron.
 */
export function electronNuxtAuthPlugin() {
	const api = !import.meta.server
		? (window as Window & { electron?: { api: ExpectedElectronApi } }).electron?.api
		: undefined

	function assertLoggedOut(method: string): void {
		if (useState(userStorageKey, () => undefined as any).value) {
			throw new Error(`${method}: a user is signed in, sign out before managing local users.`)
		}
	}

	return {
		id: "electron-nuxt-auth" as const,
		externalApiActionsKey: "electronNuxtAuthPlugin" as const,
		getActions: () => ({
			electronNuxtAuthPlugin: {
				isActive: (): boolean => !!api,
				/** Starts a login outside the app, in the system browser. */
				login: async ({
					provider,
					isDevBypass = false,
					username,
					isDevBypassRegistration = false
				}: {
					/** The provider the system browser is sent to. */
					provider?: string
					/** Use the mock sign-in instead of the real one, the server has to permit it. */
					isDevBypass?: boolean
					/** The user the mock signs in as. */
					username?: string
					/** Create the mock user already registered, so the app skips the registration page. Always true through the built in utils, see the `isDevBypassRegistration` option on {@link ExternalPlugin} for why. */
					isDevBypassRegistration?: boolean
				} = {}): Promise<void> => {
					// do not await
					// the navigation below reloads the window, and the call is already in main
					// waiting for it would only let the deeplink arrive first
					if (isDevBypass) {
						void api!.auth.mockRequestAuth({ provider, username, devBypassRegistration: isDevBypassRegistration })
					} else {
						void api!.auth.betterAuth.requestAuth({ provider })
					}
					const callbackUrl = new URL(useRuntimeConfig().public.auth.authRoutes.deeplink!, window.location.origin)
					callbackUrl.searchParams.set("provider", `${provider}`)
					await navigateTo(callbackUrl.toString(), { external: true })
				},
				local: {
					/** Every stored user, local and external, lifted to full users with a `type` marker. */
					list: async (): Promise<AuthUser[]> => {
						const now = new Date()
						const users: AuthUser[] = []
						for (const entry of await api!.users.list()) {
							// a local user is created with a name, an external one gets it when they register
							if (entry.isLocal && !entry.username) {
								// eslint-disable-next-line no-console
								console.error(`[nuxt-auth] local user ${entry.id} has no username, skipping it.`)
								continue
							}
							users.push({
								id: entry.id,
								email: "",
								emailVerified: false,
								image: null,
								isRegistered: true,
								createdAt: now,
								updatedAt: now,
								name: entry.username ?? "",
								type: entry.isLocal ? "local" : "external",
								username: entry.username ?? null
							} as AuthUser)
						}
						return users
					},
					create: async ({ id, username }: { id: string, username: string }): Promise<void> => {
						assertLoggedOut("electronNuxtAuthPlugin.local.create")
						await api!.users.create({ id, username })
					},
					/** Switches to this user, throwing if the registry no longer has them. */
					activate: async (id: string): Promise<void> => {
						assertLoggedOut("electronNuxtAuthPlugin.local.activate")
						const stored = await api!.users.list()
						if (!stored.some((entry: ElectronUserEntry) => entry.id === id)) {
							throw new Error("electronNuxtAuthPlugin.local.activate: the user no longer exists.")
						}
						await api!.users.switchUserAndSoftReload(id)
					},
					update: async (id: string, patch: {
						username?: string
						name?: string
						image?: string
					}): Promise<void> => {
						await api!.users.update({ id, patch })
					},
					delete: async (id: string): Promise<void> => {
						await api!.users.delete(id)
					}
				},
				/**
				 * Tells the app's about an external user's new profile.
				 */
				onUserUpdate: async (id: string, patch: {
					username?: string
					name?: string
					image?: string
				}): Promise<void> => {
					await api!.users.update({ id, patch })
				}
			}
		})
	}
}
