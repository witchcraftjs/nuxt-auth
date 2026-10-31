import { createError, type H3Event } from "h3"

import type { AuthUser } from "../../types.js"

/**
 * Throws a 401 when the event has no user and narrows the event type past
 * the check. Pair with `createAuthMiddleware`, which fills `context.user`.
 */
export function assertEventWithAuthorizedUser(event: H3Event): asserts event is H3Event & { context: { user: AuthUser } } {
	const user = event.context.user
	if (!user) {
		throw createError({
			statusCode: 401,
			statusMessage: "Unauthorized"
		})
	}
}
