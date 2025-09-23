import type { BaseLogger } from "@witchcraft/nuxt-logger/createUseLogger"

import type { SessionManager } from "./SessionManager.js"

import { defineEventHandler, getCookie, setCookie } from "#imports"

import type { AuthSession, AuthUser } from "../../types.js"

export function createAuthMiddleware(
	sessionManager: SessionManager,
	logger: BaseLogger
) {
	return defineEventHandler(async event => {
		const sessionId = getCookie(event, sessionManager.options.sessionCookie.name) ?? null
		if (!sessionId) {
			event.context.session = null
			event.context.user = null
			return
		}

		const { session, user, fresh } = await sessionManager.validateSessionToken(sessionId)
		logger.debug({
			ns: "auth:middleware:session",
			user,
			fresh,
			redact: { sessionId, session }
		})
		if (fresh) {
			const cookie = sessionManager.createSessionCookie(session.id)
			setCookie(event, cookie.name, cookie.value, cookie.attributes)
			// appendHeader(event, "Set-Cookie",)
		}
		if (!session) {
			const cookie = sessionManager.createBlankSessionCookie()
			setCookie(event, cookie.name, cookie.value, cookie.attributes)
			// appendHeader(event, "Set-Cookie", sessionManager.createBlankSessionCookie())
		}
		event.context.session = session
		event.context.user = user
	})
}

declare module "h3" {
	interface H3EventContext {
		user: AuthUser | null
		session: AuthSession | null
	}
}
