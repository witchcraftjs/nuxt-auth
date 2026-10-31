import { electron } from "@better-auth/electron"
import { z } from "zod"

import { postgres as db } from "#postgres"
import { createBetterAuth } from "#witchcraft-nuxt-auth/server/utils/createBetterAuth.js"
import { authAccounts, authSessions, authVerifications, users } from "~~/db/schema.js"

export const auth = createBetterAuth({
	db,
	schema: {
		users,
		authAccounts,
		authSessions,
		authVerifications
	},
	usernameSchema: z.string().min(3).max(32).regex(/^[\w.]+$/),
	maxUsernameLength: 32,
	logger: useServerLogger(),
	betterAuthOptions: {
		// llm: explain HOW setting this makes it so a live session is never rerun, i dont understand
		// a session with less than expiresIn - updateAge left is refreshed on the next read
		// which would replace the short expiry a test fakes in main
		// so a live session is never refreshed in a test run
		...(process.env.DISABLE_SESSION_REFRESH_FOR_TESTING === "true"
			? { session: { updateAge: useRuntimeConfig().public.auth.sessionExpiresAt / 1000 } }
			: {}),
		plugins: [
			electron({
				cookiePrefix: useRuntimeConfig().public.auth.cookiePrefix,
				clientID: "electron"
			})
		]
	}
})
