import { setHeader } from "h3"

import { assertEventWithAuthorizedUser } from "#witchcraft-nuxt-auth/server/utils/assertEventWithAuthorizedUser.js"

/**
 * Returns the signed in user.
 *
 * Exists so the auth middleware and the assertion helper have a route to be tested against. It is what a consumer's own handler does, and the helper is the only thing between that handler and an anonymous caller.
 */
export default defineEventHandler(event => {
	assertEventWithAuthorizedUser(event)
	setHeader(event, "cache-control", "no-store") // user data sets no-store in its own handler, as better-auth does on /get-session
	return { id: event.context.user.id, username: event.context.user.username }
})
