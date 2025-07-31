import { type SessionManager } from "./SessionManager.js"
import { defineEventHandler, getCookie, setCookie, useServerLogger } from "h3"

import { type SessionManager } from "./SessionManager.js"

import { type AuthSession, type AuthUser } from "../../types.js"

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
export function createAuthMiddleware(
	sessionManager: SessionManager,
) {
	return defineEventHandler(async event => {
		const logger = useServerLogger()

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
			redact: { sessionId , session }
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
