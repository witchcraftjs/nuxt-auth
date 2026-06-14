/* eslint-disable no-console */
import { eq } from "drizzle-orm"
import type { H3Event } from "h3"
import { z } from "zod"

import { postgres as db } from "#postgres"
import { defaultZodUsernameSchema } from "#witchcraft-nuxt-auth/types.js"

//
import { authAccounts, users } from "../../../db/schema.js"
import { sessionManager } from "../../auth.js"

export const usernameObj = z.object({
	username: defaultZodUsernameSchema
})

declare module "@witchcraft/nuxt-auth" {
	interface Register {
		// eslint-disable-next-line @typescript-eslint/naming-convention
		ApiRoutes: {
			usernameValid: string
		}
		// eslint-disable-next-line @typescript-eslint/naming-convention
		ApiRoutesParams: {
			usernameValid: Record<"username", string>
		}
	}
}

export default createAuthHandler(useRuntimeConfig(), db as any, users, authAccounts, sessionManager, useServerLogger(), {
	appUrl: "http://localhost:3000",
	onRegister: async (event: H3Event) => {
		const user = event.context.user! // already asserted
		const body = await readValidatedBody(event, usernameObj.parse)
		// double check server side
		// note usage of event.$fetch as it fowards the user's cookies
		const usernameIsValid = await event.$fetch(getAuthApiRoute(useRuntimeConfig().public, "usernameValid"), { query: { username: body.username } })
		if (!usernameIsValid) {
			throw createError({
				status: 400,
				statusMessage: "Username already taken.",
				data: {
					usernameIsValid
				}
			})
		}
		const res = await db.update(users)
			.set({ username: body.username, isRegistered: true })
			.where(eq(users.id, user.id))
		if (res instanceof Error) {
			console.error({
				ns: "auth:register",
				error: res.message
			})
			throw createError({
				status: 500,
				statusMessage: `Failed to update user: ${res.message}`
			})
		}
	},
	extendRouter: router => {
		// IMPORTANT do not actually log like this, it's for dev purposes only
		const usernameValidRoute = useRuntimeConfig().public.auth.authApiRoutes.usernameValid
		router.get(usernameValidRoute, defineEventHandler(async event => {
			Auth.assertEventWithAuthorizedUser(event)
			// user entry should exist by the time they try to register
			// this prevents endpoint getting hammered
			const user = event.context.user
			if ("username" in user && user.username) {
				throw createError({
					statusCode: 403,
					statusMessage: "Cannot change username."
				})
			}
			const query = getQuery(event)
			const res = usernameObj.safeParse(query)
			if (res.error) {
				throw createError({
					statusCode: 400,
					statusMessage: "Invalid body." + JSON.stringify(res.error)
				})
			}
			const username = res.data.username
			const isValid = defaultZodUsernameSchema.safeParse(username)
			console.info({ ns: "auth:usernameValid:satisfiesSchema", username, isValid })
			if (!username || !isValid.success) return false
			console.trace({
				ns: `auth:${usernameValidRoute}`,

				username
			})
			const usernameExists = await db.select()
				.from(users)
				.where(
					eq(users.username, username)
				)
				.limit(1)

			console.info({ ns: "auth:usernameValid:exists", usernameExists })
			return usernameExists.length === 0
		}))
		router.post("/users/remove", defineEventHandler(async event => {
			Auth.assertEventWithAuthorizedUser(event)
			const user = event.context.user
			console.info({ ns: "auth:dev-remove-user", user })
			await db.delete(users).where(eq(users.id, user.id))
			return true
		}))
	}
})
