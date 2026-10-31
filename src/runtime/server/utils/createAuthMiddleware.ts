import type { Auth } from "better-auth"
import { defineEventHandler } from "h3"

import type { AuthSession } from "./createAuthSchema.js"

import type { AuthUser } from "../../types.js"

export function createAuthMiddleware(auth: Auth<any>, logger: any) {
	return defineEventHandler(async event => {
		try {
			const session = await auth.api.getSession({
				headers: event.headers
			})
			if (session) {
				event.context.user = session.user as AuthUser
				event.context.session = session.session as AuthSession
			} else {
				event.context.user = null
				event.context.session = null
			}
		} catch (e) {
			logger?.error?.({ ns: "auth:middleware", error: e })
			event.context.user = null
			event.context.session = null
		}
	})
}

declare module "h3" {
	interface H3EventContext {
		user: AuthUser | null
		session: AuthSession | null
	}
}
