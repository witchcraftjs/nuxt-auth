import { APIError, createAuthEndpoint, createAuthMiddleware } from "better-auth/api"
import { setSessionCookie } from "better-auth/cookies"
import { z } from "zod"

/**
 * The username a bypassed mock user gets when the caller passes an id but no username.
 *
 * It is designed to satisfy the default schema and maxLength.
 */
function derivedUsername(id: string, maxUsernameLength: number): string {
	return `username_${id.replace(/\W/g, "").slice(0, maxUsernameLength - "username_".length)}`
}

export function devMock(
	{
		generateUser,
		authRoutes,
		enabledProviders,
		usernameValidator,
		maxUsernameLength = 32,
		transferCodeTtlMs = 1000 * 60 * 5
	}: {
		generateUser?: (() => any)
		authRoutes: any
		/** The providers the app configured, any other name is refused. */
		enabledProviders: string[]
		/** The app's username schema, so a bypassed user cannot pick a name the app would refuse. */
		usernameValidator?: (username: string) => Promise<boolean>
		/** Longest username the mock name builder emits, defaults to 32. */
		maxUsernameLength?: number
		/** How long a transfer code stays valid, defaults to 5 minutes. */
		transferCodeTtlMs?: number
	}
) {
	/** The mock stands in for a provider, so it only answers for a provider the app actually configured. */
	function assertConfiguredProvider(provider: string | undefined): void {
		if (provider && enabledProviders.includes(provider)) return
		throw new APIError("BAD_REQUEST", {
			message: `Unknown provider "${provider ?? ""}", the mock only serves the configured ones: ${enabledProviders.join(", ")}.`
		})
	}

	/**
	 * Finds the user a request refers to, or creates one.
	 *
	 * A request that does not bypass registration is an unregistered user: no username, and `name` is its id.
	 *
	 * A request that bypasses registration creates a registered user, so it needs a username, and bypassing is only possible while that user is created.
	 */
	async function resolveUser(ctx: any, {
		username,
		id,
		devBypassRegistration
	}: {
		username: string | undefined
		id: string | undefined
		devBypassRegistration: boolean
	}) {
		// a field the caller sent empty is the same as one it did not send
		username ||= undefined
		if (username && usernameValidator && !await usernameValidator(username)) {
			throw new APIError("BAD_REQUEST", {
				message: `"${username}" is not a valid username for this app.`
			})
		}
		if (!devBypassRegistration && username) {
			throw new APIError("BAD_REQUEST", {
				message: "A request that does not bypass registration cannot carry a username, the user picks one when they register."
			})
		}

		const user = id
			? await ctx.context.adapter.findOne({ model: "user", where: [{ field: "id", value: id }] })
			: username
				? await ctx.context.adapter.findOne({ model: "user", where: [{ field: "username", value: username }] })
				: undefined
		if (user) {
			if (devBypassRegistration) {
				throw new APIError("BAD_REQUEST", {
					message: "Registration can only be bypassed while the user is created."
				})
			}
			return user
		}

		const generated = generateUser?.()
		const resolvedId = id ?? generated?.id ?? crypto.randomUUID()
		const resolvedUsername = devBypassRegistration
			? username ?? generated?.username ?? derivedUsername(resolvedId, maxUsernameLength)
			: undefined
		return await ctx.context.internalAdapter.createUser({
			...generated,
			id: resolvedId,
			email: generated?.email ?? `${resolvedUsername ?? resolvedId}@dev.local`,
			// a registered user is named after their username, an unregistered one has only an id
			name: resolvedUsername ?? generated?.name ?? resolvedId,
			username: resolvedUsername,
			image: generated?.image ?? null,
			emailVerified: true,
			isRegistered: devBypassRegistration
		})
	}

	/**
	 * Same code an external auth plugin issues after a real sign-in, redeemable at
	 * its token endpoint. Returned as the deeplink url the app would have been
	 * sent by the plugin's redirect cookie, so no browser round trip is needed.
	 *
	 * The verification prefix comes from the caller, it must match what the app's
	 * token endpoint consumes.
	 */
	async function transferToExternal(ctx: any, user: any, {
		codeChallenge,
		state,
		verificationPrefix,
		deeplinkScheme
	}: {
		codeChallenge: string
		state: string
		verificationPrefix: string
		deeplinkScheme: string
	}) {
		const identifier = crypto.randomUUID()
		await ctx.context.internalAdapter.createVerificationValue({
			identifier: `${verificationPrefix}:${identifier}`,
			value: JSON.stringify({ userId: user.id, codeChallenge, state }),
			expiresAt: new Date(Date.now() + transferCodeTtlMs)
		})
		const token = Buffer.from(JSON.stringify({ identifier, state })).toString("base64url")
		return `${deeplinkScheme}://${authRoutes.deeplink.replace(/^\//, "")}#token=${token}`
	}

	function redirectFor(user: any, devBypassRegistration: boolean): string {
		return !user.isRegistered && !devBypassRegistration
			? authRoutes.register
			: authRoutes.postRegisteredLogin
	}

	return {
		id: "dev-mock",
		hooks: {
			before: [{
				matcher: (context: any) => {
					return typeof context?.path === "string" && context.path.startsWith("/callback/")
						&& context?.query?.devBypass === "true"
				},
				handler: createAuthMiddleware(async (ctx: any) => {
					// the hook context carries the route pattern `/callback/:id`, the provider is in its params
					assertConfiguredProvider(ctx.params?.id)
					const query = (ctx.query ?? {}) as Record<string, string>
					const id = query.id
					const devBypassRegistration = query.devBypassRegistration === "true"
					const user = await resolveUser(ctx, {
						username: query.username,
						id,
						devBypassRegistration
					})
					const session = await ctx.context.internalAdapter.createSession(user.id, ctx.request)
					await setSessionCookie(ctx, { session, user }, false)
					return ctx.redirect(redirectFor(user, devBypassRegistration))
				})
			}]
		},
		endpoints: {
			devMock: createAuthEndpoint("/dev/mock", {
				method: "POST",
				body: z.object({
					username: z.string().optional(),
					id: z.string().optional(),
					provider: z.string(),
					code_challenge: z.string().optional(),
					state: z.string().optional(),
					verification_prefix: z.string().optional(),
					deeplink_scheme: z.string().optional(),
					devBypassRegistration: z.boolean().optional()
				})
			}, async (ctx: any) => {
				assertConfiguredProvider(ctx.body.provider)
				const {
					code_challenge: codeChallenge,
					state,
					verification_prefix: verificationPrefix,
					deeplink_scheme: deeplinkScheme,
					devBypassRegistration
				} = ctx.body
				const id = ctx.body.id as string | undefined
				const user = await resolveUser(ctx, {
					username: ctx.body.username as string | undefined,
					id,
					devBypassRegistration: devBypassRegistration ?? false
				})

				if (codeChallenge && state) {
					if (!deeplinkScheme) throw new Error("Mock transfer needs a deeplink_scheme.")
					const url = await transferToExternal(ctx, user, { codeChallenge, state, verificationPrefix: verificationPrefix ?? "external", deeplinkScheme })
					return ctx.json({ redirectUrl: url })
				}

				const session = await ctx.context.internalAdapter.createSession(user.id, ctx.request)
				await setSessionCookie(ctx, { session, user }, false)
				return ctx.json({ redirectUrl: redirectFor(user, devBypassRegistration ?? false) })
			}),
			/**
			 * Moves the session row's expiry back, so a test can run a short session without
			 * waiting for a real one.
			 *
			 * The token has to arrive as a `Cookie` header (`headers: { cookie: "name=value" }`),
			 * because `getSignedCookie` reads the request's parsed cookies and a signed value in a
			 * body cannot be verified by it. Without the header it finds no cookie and updates
			 * nothing.
			 */
			devMockSession: createAuthEndpoint("/dev/mock/session", {
				method: "POST",
				body: z.object({
					/** Epoch ms, the only unit that crosses the wire. `Session.expiresAt` is a date. */
					expiresAt: z.number()
				})
			}, async (ctx: any) => {
				const token = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret)
				if (!token) return ctx.json({ updated: false })
				await ctx.context.internalAdapter.updateSession(token, { expiresAt: new Date(ctx.body.expiresAt) })
				return ctx.json({ updated: true })
			})
		}
	}
}
