import { createSelectSchema } from "drizzle-zod"
import type { InjectionKey } from "vue"
import { z } from "zod"

import { createAuthUserSchema } from "./server/utils/createAuthSchema.js"

export type * from "./server/utils/createAuthSchema.js"

export const authUsersDbSchema = createAuthUserSchema()

/** The db row, what the server sends. */
const zAuthUserDb = createSelectSchema(authUsersDbSchema)

export type AuthUserFields = typeof authUsersDbSchema.$inferSelect

// makes it easy for end users to re-create the type if they override the base schema
export const zAdditionalLocalUserProperties = z.object({
	/**
	 * Client-side only marker for who resolved the user, never a db column.
	 *
	 * `"local"` is written where a local-only user is created (see the local-users client
	 * plugin). `"external"` is written by electron main when it persists an exchanged user.
	 * Absent means the app got the user from the server, i.e. a web user.
	 */

	type: z.enum(["local", "external"]).optional(),
	createdAt: z.date(),
	updatedAt: z.date()
})

export const zAdditionalLocalStoredUserProperties = zAdditionalLocalUserProperties.extend({
	// because they are saved as ISO strings
	createdAt: z.string(),
	updatedAt: z.string()
})

const zAuthUserClient = zAuthUserDb.extend(zAdditionalLocalUserProperties.shape)

/** Local-only user. Always has a username, it is the name it was created with. */
export const zAuthUserLocal = zAuthUserClient.extend({
	type: z.literal("local"),
	username: z.string()
})

/** User the server resolved. Username is optional, better-auth's column is nullable. */
export const zAuthUserExternal = zAuthUserClient.extend({
	type: z.optional(z.literal("external")),
	username: z.string().nullable()
})

/** Any user the client holds, local or external. */
export const zAuthUser = z.discriminatedUnion("type", [zAuthUserLocal, zAuthUserExternal])

const zAuthUserStoredBase = zAuthUserDb.partial({
	image: true,
	username: true
}).extend(zAdditionalLocalStoredUserProperties.shape)

export const zAuthUserLocalStored = zAuthUserStoredBase.extend({
	type: z.literal("local"),
	username: z.string()
})

export const zAuthUserExternalStored = zAuthUserStoredBase.extend({
	type: z.optional(z.literal("external")),
	username: z.string().nullable()
})

/** Any user the client holds, as it is stored, i.e. dates are ISO strings. */
export const zAuthUserStored = z.discriminatedUnion("type", [zAuthUserLocalStored, zAuthUserExternalStored])


export type AuthUser = z.infer<typeof zAuthUser>

export type AuthUserStored = z.infer<typeof zAuthUserStored>

export type AuthLocalUser = z.infer<typeof zAuthUserLocal>

export type AuthLocalUserStored = z.infer<typeof zAuthUserLocalStored>

// camel-case for our two consumers, electron's `session.cookies.set` and better-auth's cookie `attributes`.
// not better-auth's lowercase `CookieAttributes` (its camel-case twin is not exported).
// electron must translate `sameSite: "none"` to `"no_restriction"`, see `_cookieSetOpts`.
export type SessionCookieOptions = {
	secure?: boolean
	path?: string
	sameSite?: "lax" | "strict" | "none"
	maxAge?: number
	expires?: Date
	partitioned?: boolean
}

/** Where the window keeps the expiry electron main put on the session cookie, in ms. External users only. */
export const externalExpiryStorageKey = "auth:external:expiresAt"

/** Signed-in user, shared by `useState` and `localStorage`, the two must stay the same string. */
export const userStorageKey = "auth:user"

/** Local-only users list, see the local-users client plugin. */
export const localOnlyUsersStorageKey = "auth:localOnlyUsers"

/** Expired flag, shared by state. */
export const isExpiredStateKey = "auth:isExpired"

/** Fetch gate, shared by state. */
export const fetchStateKey = "auth:_fetch"

/** Username validation id. */
export const usernameValidFetchKey = "auth:username:valid"

export const defaultZodUsernameSchema = z.string()
	.min(3)
	.max(32)
	.regex(/^[\w.]+$/, "Username can only contain letters, numbers, underscores, and periods.")


export type ProviderStyle = {
	name: string
	logo: any
	class?: string
}

export const providerStylesInjectionKey = Symbol.for("@witchcraft/nuxt-auth:providerStyles") as InjectionKey<Partial<Record<string, Partial<ProviderStyle>>>>

/** An external platform's api, exposed on the auth client by a better-auth client plugin under its `externalApiActionsKey`. */
export type ExternalPlugin = {
	/** Should return true when the plugin is on it's platform (e.g. `isElectron()`). `useAuth` uses the first active one. */
	isActive: () => boolean
	/** Starts a login outside the app. Should take over the external branch of `login`. */
	login: (options: {
		provider?: string
		/** If a devBypass login was requested you need to handle it. */
		isDevBypass?: boolean
		/**
		 * If a devBypassRegistration login was requested you need to handle it.
		 *
		 * Typically the external app should mock the entire browser side flow by bypassing it (see the electron diagram in the readme). Relying on the browser side mock is complicated because the testing app must be installed to be able to handle the deeplink.
		 *
		 * So the first approach is easier but it does mean you cannot mock without bypassing registration. This is because the real flow is app => browser (login => register) => app. Registration is a browser page always and should not be included in the app.
		 *
		 * If you tried to not handle this you would find yourself including the registration page on the app which is nothing like the real production flow.
		 */
		isDevBypassRegistration?: boolean
		/** The user the mock signs in as. */
		username?: string
	}) => Promise<void>
	/** Records an external profile change in the platform registry. */
	onUserUpdate: (id: string, patch: {
		username?: string
		name?: string
		image?: string
	}) => Promise<void> | void
	/** For overriding how local users are stored/created only when the plugin is active. Absent means the default store handles local users. */
	local?: {
		list: () => Promise<AuthUser[]> | AuthUser[]
		create: (user: { id: string, username: string }) => Promise<void> | void
		activate: (id: string) => Promise<void> | void
		update: (id: string, patch: {
			username?: string
			name?: string
			image?: string
		}) => Promise<void> | void
		delete: (id: string) => Promise<void> | void
	}
}

