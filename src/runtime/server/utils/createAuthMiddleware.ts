import { isValidRequestOrigin } from "./isValidRequestOrigin.js"
import { type SessionManager } from "./SessionManager.js"
import { defineEventHandler, getCookie, setCookie, useServerLogger } from "h3"


import { type AuthSession, type AuthUser } from "../../types.js"

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
export function createAuthMiddleware(sessionManager: SessionManager) {
	return defineEventHandler(async event => {
		const logger = useServerLogger()
		const originHeader = getHeader(event, "Origin") ?? null
		const requestMethod = event.node.req.method?.toUpperCase()
		const requestPath = event.node.req.url
		const originIp = getRequestIP(event)

		let skipOriginValidation = false

		const allowed: AuthMiddlewareExclusion[] = [
			...(options.allow ?? []),
			...(allowedMiddlewareExclusions ?? []),
		]
		for (const exclusion of allowed) {
			const pathMatches = exclusion.paths.some(path => path === requestPath)
			const methodMatches = !exclusion.methods || (requestMethod && exclusion.methods.includes(requestMethod))
			const originMatches =
			(originHeader === null && exclusion.allowedOrigins.some(_ => _ === null || _ === "null"))
			|| isValidRequestOrigin(originHeader, exclusion.allowedOrigins)

			const ipMatches = !exclusion.allowedIps || (originIp && exclusion.allowedIps.includes(originIp))


			if (pathMatches && methodMatches && originMatches && ipMatches) {
				skipOriginValidation = true
				break
			}
		}
		if (!skipOriginValidation && event.node.req.method !== "GET") {
			if (!isValidRequestOrigin(originHeader, ["http://localhost:3000"])) {
				logger.debug({
					ns: "auth:middleware:origin:blocked",
					originHeader,
					method: event.node.req.method,
				})
				return event.node.res.writeHead(403).end()
			}
		}
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
