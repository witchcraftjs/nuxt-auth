import { eq } from "drizzle-orm"
import type { H3Event } from "h3"
import { z } from "zod"

import { defaultZodUsernameSchema } from "#auth/types.js"
import { postgres as db } from "#postgres"

//
import { authAccounts, users } from "../../../db/schema.js"
import { sessionManager } from "../../auth.js"

export const registerBody = z.object({
	username: z.string(),
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
const logger = useServerLogger()

export default createAuthHandler(db as any, users, authAccounts, sessionManager, {
	onRegister: async (event: H3Event) => {
		const user = event.context.user! // already asserted
		const body = await readValidatedBody(event, registerBody.parse)
		const usernameIsValid = await $fetch(getAuthApiRoute(useRuntimeConfig().public, "usernameValid", { username: body.username }))
		if (!usernameIsValid) {
			throw createError({
				status: 400,
				statusMessage: "Username already taken.",
				data: {
					usernameIsValid,
				}
			})
		}
		const res = await db.update(users)
			.set({ username: body.username, isRegistered: true, })
			.where(eq(users.id, user.id))
		if (res instanceof Error) {
			logger.error({
				ns: "auth:register",
				error: res.message,
			})
			throw createError({
				status: 500,
				statusMessage: `Failed to update user: ${res.message}`,
			})
		}
	},
	extendRouter: router => {
		const usernameValidRoute = useRuntimeConfig().public.auth.authApiRoutes.usernameValid
		router.get(usernameValidRoute, defineEventHandler(async event => {
			const username = event.context.params?.username
			const isValid = defaultZodUsernameSchema.safeParse(username)
			logger.info({ ns: "auth:usernameValid:satisfiesSchema", username, isValid })
			if (!username || !isValid.success) return false
			logger.trace({
				ns: `auth:${usernameValidRoute}`,
				username
			})
			const usernameExists = await db.select()
				.from(users)
				.where(
					eq(users.username, username)
				)
				.limit(1)

			logger.info({ ns: "auth:usernameValid:exists", usernameExists })
			return usernameExists.length === 0
		}))
	}
})
