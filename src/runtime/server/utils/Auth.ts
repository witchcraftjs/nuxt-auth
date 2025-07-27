import { capitalize } from "@alanscodelog/utils/capitalize.js"
import { unreachable } from "@alanscodelog/utils/unreachable.js"
import { generateState, type OAuth2RequestError, type OAuth2Tokens, } from "arctic"
import { type CookieSerializeOptions } from "cookie-es"
import { and,eq } from "drizzle-orm"
import { type PgDatabase } from "drizzle-orm/pg-core"
import type { EventHandler, H3Event, Router } from "h3"
import { createError, defineEventHandler, getCookie, setCookie } from "h3"
import { type JwtPayload } from "jsonwebtoken"
import { type Logger } from "pino"
import { z } from "zod"

import { type SessionManager } from "./SessionManager.js"

import { getSafeSecretsInfo } from "#auth/server/helpers/getSafeSecretsInfo.js"
import { logSafeRoute } from "#auth/server/helpers/logSafeRoute.js"
import {
	type AuthOptions,
	type AuthSession,
	type AuthUser,
	type BaseProviderAccountInfo,
	type ProviderHandler,
	type ProviderNames,
} from "#auth/types"
import { AUTH_ERROR } from "#auth/types"

import { type AuthAccountsTable,type UserTable } from "../../server/utils/createAuthSchema.js"
import { getAuthApiRoute } from "../../utils/getAuthApiRoute.js"
import { signJwt } from "../helpers/signJwt.js"
import { verifyJwt as jwtVerify } from "../helpers/verifyJwt.js"

export const zState = z.object({
	oauthState: z.string(),
	additionalState: z.any(),
	deeplink: z.string().optional(),
})

type State = z.infer<typeof zState>


export const oauth2CallbackQuery = z.object({
	code: z.string(),
	state: z.string(),
})

const rc = useRuntimeConfig()

export const providerCookieOpts: CookieSerializeOptions = {
	secure: useRuntimeConfig().public.auth.isSecure,
	...rc.public.auth.providerCookieOpts
}

export class Auth {
	validRoutes: string[] = []

	providers: Record<string, ProviderHandler<"oauth2"> | ProviderHandler<"oauth2_pcke">>

	handlers: AuthOptions["handlers"]

	externalAccessTokenExpiresIn: AuthOptions["externalAccessTokenExpiresIn"] = "10m"

	deeplinkSchemes: Record<string, string>

	onRegister?: (
		event: H3Event,
		/** Route the handler will redirect to (without the deeplink query param). */
		route: string,
		/** The deeplink query param, if any. */
		deeplink?: string
	) => Promise<boolean>

	eventHandler: EventHandler

	getAdditionalState?: AuthOptions["additionalState"]

	modifyCallbackRedirect?: AuthOptions["modifyCallbackRedirect"]

	devBypassAuth?: AuthOptions["devBypassAuth"]

	createMockUser: AuthOptions["createMockUser"]

	generateUser: AuthOptions["generateUser"]

	static defaultCreateMockUser(_username: string | undefined,id: string | undefined, provider: string): Omit<BaseProviderAccountInfo, "userId"> {
		if (!id && !_username) throw new Error("Either id or username must be provided")
		const username = _username ?? `username-${id}`
		return {
			provider,
			providerId: `dev-${provider}-${username}`,
			email: `dev-${provider}-${username}@dev.com`,
			isVerified: true,
			name: `Dev ${username}`,
			info: null
		}
	}

	db: PgDatabase<any, any, any>

	usersTable: UserTable

	authAccountsTable: AuthAccountsTable

	sessionManager: SessionManager

	router: Router

	logger: Logger

	constructor(
		db: Auth["db"],
		usersTable: Auth["usersTable"],
		authAccountsTable: Auth["authAccountsTable"],
		sessionManager: Auth["sessionManager"],
		router: Auth["router"],
		opts: AuthOptions,
		env: Record<`auth${string}${"ClientId" | "ClientSecret"}` | string, string>,
		logger: Logger,
	) {
		this.logger = useServerLogger()
		this.db = db
		this.usersTable = usersTable
		this.authAccountsTable = authAccountsTable
		this.sessionManager = sessionManager
		this.router = router
		this.onRegister = opts.onRegister
		if (opts.additionalState) {
			this.getAdditionalState = opts.additionalState
		}
		if (opts.devBypassAuth) this.devBypassAuth = opts.devBypassAuth
		this.generateUser = opts.generateUser
		this.createMockUser = opts.createMockUser ?? Auth.defaultCreateMockUser

		this.modifyCallbackRedirect = opts.modifyCallbackRedirect
		this.deeplinkSchemes = opts.deeplinkSchemes ?? {}
		for (const val of Object.values(this.deeplinkSchemes)) {
			if (!val.endsWith(":")) {
				throw createError({
					status: 500,
					statusMessage: "Invalid deeplink scheme. Scheme protocol should end with a colon.",
					data: { code: AUTH_ERROR.INVALID_DEEPLINK },
				})
			}
		}

		const {
			baseUrl,
			handlers,
			providerOptions,
			enabledProviders,
		} = {
			baseUrl: import.meta.dev ? `${useRuntimeConfig().public.auth.isSecure ? "https" : "http"}://localhost:3000` : undefined,
			...opts,
		}
		if (baseUrl === undefined) {
			throw createError({
				status: 500,
				statusMessage: "No baseurl defined.",
			})
		}

		this.handlers = handlers
		this.providers = {}

		for (const provider of enabledProviders) {
			const capitalized = capitalize(provider)
			const clientId = env[`auth${capitalized}ClientId`]
			const clientSecret = env[`auth${capitalized}ClientSecret`]

			if (!clientId || !clientSecret) {
				this.logger.warn({
					ns: "auth:init:missingSecrets",
					env,
					error: `Missing auth${capitalized}ClientId or auth${capitalized}ClientSecret for ${capitalized}. Disabling.` })
				continue
			}
			const options = providerOptions?.[provider]
			const redirectUri = baseUrl + getAuthApiRoute("callback", { provider: provider.toLowerCase() })
			const providerClass = this.handlers[provider]
			if (!providerClass) {
				this.logger.error({
					ns: "auth:init",
					provider,
				})
				throw createError({
					status: 500,
					statusMessage: `Unknown provider: ${provider}`,
					data: { code: AUTH_ERROR.UNKNOWN_PROVIDER },
				})
			}
			this.providers[provider] = new providerClass({ clientId, clientSecret, redirectUri }, options as any)
		}
		this.logger.info({
			ns: "auth:init",
			enabledProviders,
			registeredProviders: Object.keys(this.providers),
			baseUrl,
			isSecure: useRuntimeConfig().public.auth.isSecure,
			...getSafeSecretsInfo()
		})


		const apiRoutes = rc.public.auth.authApiRoutes
		const authRoutes = rc.public.auth.authRoutes


		router.get(apiRoutes.usersInfo, defineEventHandler(event => {
			const user = event.context.user!
			const id = getCookie(event, "userId")
			this.logger.debug({
				ns: "auth:users/info",
				userExists: !!user,
				redact: { user, id, authSession: getCookie(event, "authSession") }
			})

			return user ?? false
		}))

		router.get(apiRoutes.externalExchange, defineEventHandler(async event => {
			const accessToken = getRequestHeader(event, "Authorization")?.slice("Bearer ".length)

			const decoded = await this.verifyAccessToken(accessToken)
				.catch((err: Error) => createError({
					status: 400,
					statusMessage: err.message,
					data: { code: AUTH_ERROR.INVALID_ACCESS_TOKEN },
				})) as {
				userId: string
			}
			if (decoded instanceof Error) throw decoded

			const res = await this.createSession(event, decoded.userId)
			this.logger.debug({
				ns: "auth:callback:createdSession",
				redact: { res, decoded }
			})

			// this is returned like this because using node's fetch, createError doesn't throw
			// it returns json, so this way we can read the reply by just doing res.json()
			// todo, investigate why this is

			return { token: res.token }
		}))

		router.get(apiRoutes.usersIdAccounts, defineEventHandler(async event => {
			const id = event.context.user?.id
			Auth.assertAuthorizedUserAndId(event.context.user, id)

			this.logger.trace({
				ns: "auth:users/:id/account",
			})

			const accounts = await this.db.select().from(this.authAccountsTable).where(and(
				eq(this.authAccountsTable.userId, id),
			))
			return accounts
		}))
		router.post(apiRoutes.logout, defineEventHandler(async event => {
			this.logger.trace({
				ns: "auth:users/logout",
				session: event.context.session !== undefined,
			})

			if (!event.context.session) {
				throw createError({
					statusCode: 403,
					statusMessage: "Not logged in."
				})
			}
			await this.sessionManager.invalidateSession(event.context.session.id)
			const emptyCookie = this.sessionManager.createBlankSessionCookie()
			deleteCookie(event, `userId`, emptyCookie.attributes)
			deleteCookie(event, emptyCookie.name, emptyCookie.attributes)
			return true
		}))

		router.get(apiRoutes.login, defineEventHandler(async event => {
			const providerName = event.context.params!.provider
			this.assertValidProvider(providerName)

			const query = getQuery(event)
			const devBypassAuth = query.devBypass === "true" && this.devBypassAuth === true
			const deeplink = getQuery(event).deeplink

			if (devBypassAuth) {
				return sendRedirect(event, `${authRoutes.mockAuth}?provider=${providerName}${deeplink ? `&deeplink=${deeplink}` : ""}`)
			}

			const state = {
				oauthState: generateState(),
				additionalState: this.getAdditionalState?.(event),
				deeplink: typeof deeplink === "string" ? deeplink : undefined,
			}
			const encodedState = this.encodeState(state)
			const info = this.getProvider(providerName).getLoginInfo(encodedState)

			this.logger.debug({
				ns: "auth:login",
				provider: providerName,
				redact: {
					url: info.url.toString(),
					state,
					encodedState,
					codeVerifier: "codeVerifier" in info && info.codeVerifier,
					deeplink
				}
			})
			try {
				if (info.type === "oauth2" || info.type === "oauth2_pcke") {
					setCookie(event, `${providerName}_oauth_state`, state.oauthState, providerCookieOpts)
				}
				if (info.type === "oauth2_pcke") {
					setCookie(event, `${providerName}_oauth_code_verifier`, info.codeVerifier, providerCookieOpts)
				}
			} catch (e) {
				this.logger.error({
					ns: "auth:login:setCookieError",
					error: e instanceof Error ? e.message : "Not an error type.",
					redact: {
						error: e,
						oauth2: [event, `${providerName}_oauth_state`, state.oauthState, providerCookieOpts],
						// eslint-disable-next-line camelcase
						oauth2_pcke: [ event, `_oauth_code_verifier ${providerName}`, info.type === "oauth2_pcke" ? info.codeVerifier : undefined, providerCookieOpts ],
					}

				})
			}
			return sendRedirect(event, info.url.toString())
		}))
		router.get(apiRoutes.callback, defineEventHandler(async event => {
			const providerName = event.context.params!.provider
			this.assertValidProvider(providerName)
			const provider = this.getProvider(providerName)

			const redirectToLogin = { redirect: rc.public.auth.authRoutes.login }
			const query = getQuery(event)

			const devBypassAuth = this.devBypassAuth && query.devBypass === "true"
			const bypassDeeplink = devBypassAuth ? query.deeplink as string : undefined
			const bypassUser = devBypassAuth ? query.username : undefined
			const bypassId = devBypassAuth ? query.id : undefined
			// this is updated if we find a registered user
			let bypassRegistration = devBypassAuth ? query.devBypassRegistration === "true" : false

			const res = devBypassAuth
			? { tokens: undefined, additionalState: undefined, deeplink: bypassDeeplink }
			:	provider.type === "oauth2" // :/
			? await this.handleOAuth2(event, provider as ProviderHandler<"oauth2">, redirectToLogin)
			: await this.handleOAuth2Pcke(event, provider as ProviderHandler<"oauth2_pcke">, redirectToLogin)
			const { tokens, additionalState, deeplink } = res

			const mockUser = devBypassAuth
			? {
				...Auth.defaultCreateMockUser(bypassUser as string,bypassId as string, providerName),
				...((await this.createMockUser!(bypassUser as string,bypassId as string, providerName)) ?? {}),
			} satisfies Omit<BaseProviderAccountInfo, "userId"> : undefined
			const userInfo = devBypassAuth
				? mockUser
				: await provider.getAccountInfo(tokens)
					.catch((e: any) => {
						this.logger.error({
							ns: "auth:callback:getUserInfoError",
							redact: {
								error: e,
							},
							error: e.message,
						})
						throw createError({
							status: 400,
							statusMessage: "Error fetching provider user info.",
							data: { ...redirectToLogin }
						})
					})

			if (!userInfo) unreachable()

			const existingProviderAccount = (await this.db.select({
				id: this.authAccountsTable.userId,
			})
				.from(this.authAccountsTable)
				.where(
					and(
						eq(this.authAccountsTable.provider, provider.name),
						eq(this.authAccountsTable.providerId, userInfo.providerId),
					)
				))[0]

			const existingUserAccount = (await this.db.select({
				id: this.usersTable.id,
				isRegistered: this.usersTable.isRegistered,
			})
				.from(this.usersTable)
				.where(
					eq(this.usersTable.email , userInfo!.email),
				))[0]

			const isRegistered = existingUserAccount?.isRegistered ?? false
			bypassRegistration = bypassRegistration ? true : isRegistered
			let sessionUserId: string | undefined = existingProviderAccount?.id ?? existingUserAccount?.id

			this.logger.debug({
				ns: "auth:callback",
				provider: providerName,
				redact: {
					userInfo,
					existingProviderAccount: !!existingProviderAccount,
					existingUserAccount: !!existingUserAccount,
					isRegistered,
					sessionUserId,
					additionalState,
					deeplink,
					tokens,
					devBypassAuth,
					bypassDeeplink,
					bypassUser,
					bypassRegistration,
				}
			})


			if (event.context.user && existingProviderAccount) {
				this.logger.debug({
					ns: "auth:callback:existingProviderAccount"
				})
				// await this.createSession(event, sessionUserId!)
				return this.createRedirect(
					event,
					sessionUserId!,
					isRegistered,
					additionalState,
					deeplink!
				)
			// throw createError({
			// 	status: 400,
			// 	message: `Account already linked to ${provider.name} provider.`,
			// 	data: { redirect: "/", code: AUTH_ERROR_CODES.ACCOUNT_ALREADY_LINKED },
			// })
			}


			if (existingProviderAccount) {
				this.logger.debug({
					ns: "auth:callback:existingUser:existingAccount"
				})
			} else if (existingUserAccount) {
				this.logger.debug({
					ns: "auth:callback:existingUser:newProvider",
					isRegistered,
				})
				await this.db.insert(this.authAccountsTable).values({
					userId: sessionUserId,
					...userInfo,
					...(isRegistered ? {} : { info: userInfo!.info })
				}).catch(e => {
					throw createError({
						statusMessage: `Failed to add provider account ${provider.name}: ${e.message}`,
						status: 500,
						data: { ...redirectToLogin, code: AUTH_ERROR.FAILED_TO_ADD_PROVIDER_ACCOUNT },
					})
				})
			} else {
				this.logger.debug({
					ns: "auth:callback:newUser",
					existingUserAccount,
					existingProviderAccount,
				})

				const userId = await this.db.transaction(async tx => {
				// eslint-disable-next-line @typescript-eslint/no-shadow
					const userId = (await tx.insert(this.usersTable).values({
						...(this.generateUser?.() ?? {}),
						email: userInfo!.email,
						isRegistered: bypassRegistration,
						...(bypassRegistration ? { username: bypassUser } : {}),
					}).returning({ userId: this.usersTable.id }))[0]?.userId

					if (!userId) {
						tx.rollback()
						return
					}
					await tx.insert(this.authAccountsTable).values({
						userId,
						...userInfo!,
					})
					return userId
				})

				if (!userId) {
					this.logger.error({
						ns: "auth:callback:newUser:failed",
					})
					throw createError({
						statusMessage: "Failed to create user.",
						status: 500,
						data: { ...redirectToLogin, code: AUTH_ERROR.FAILED_TO_CREATE_USER },
					})
				}
				sessionUserId = userId
			}
			if (!sessionUserId || typeof sessionUserId !== "string") unreachable()
			await this.createSession(event, sessionUserId!)
			return this.createRedirect(
				event,
				sessionUserId,
				bypassRegistration ?? isRegistered,
				additionalState,
				deeplink
			)
		}))
		router.post(apiRoutes.register, defineEventHandler(async event => {
			if (!this.onRegister) {
				throw createError({ status: 500, statusMessage: "No onRegister handler." })
			}
			Auth.assertAuthorizedUser(event.context.user)
			if (event.context.user?.isRegistered) {
				throw createError({
					status: 400,
					statusMessage: "User is already registered.",
					data: { code: AUTH_ERROR.USER_ALREADY_REGISTERED },
				})
			}
			let deeplink = getQuery(event).deeplink
			deeplink = typeof deeplink === "string" ? deeplink : undefined

			const route = deeplink
				? rc.public.auth.authRoutes.externalCode
				: rc.public.auth.authRoutes.postRegisteredLogin


			const res = await this.onRegister(event, route, deeplink)

			if (res === undefined || !res) {
				return {
					redirectUrl: this.getRedirect(route, true, deeplink, await this.createAccessToken(event.context.user.id)),
				}
			} else {
				return res
			}
		}))

		opts.extendRouter?.(router)

		this.logger.debug({
			ns: "auth:routes",
			apiRoutes
		})
		if (import.meta.dev) {
			router.get("/test", defineEventHandler(async _event => "Dev Only Route: Api router working."))
		}
		this.eventHandler = useBase(apiRoutes.base, event => {
			const routePath = event.context.params?._
			this.logger.debug({
				ns: "auth:route",
				route: routePath && logSafeRoute(routePath),
			})

			return router.handler(event)
		})
	}


	assertValidProvider(provider?: string): asserts provider is ProviderNames {
		if(!provider || this.providers[provider] === undefined) {
			this.logger.error({
				ns: "auth:assertValidProvider",
				provider,
			})
			throw createError({
				status: 400,
				statusMessage: `Invalid provider: ${provider}, known: ${Object.keys(this.providers).join(", ")}`,
				data: { code: AUTH_ERROR.UNKNOWN_PROVIDER },
			})
		}
	}

	getProvider(provider: ProviderNames): ProviderHandler<"oauth2"> | ProviderHandler<"oauth2_pcke"> {
		return this.providers[provider]!
	}

	static assertAuthorizedUser(user: AuthUser | undefined | null): asserts user is AuthUser {
		if (!user) {
			throw createError({
				statusCode: 401,
				statusMessage: "Unauthorized"
			})
		}
	}

	static assertEventWithAuthorizedUser(event: H3Event): asserts event is H3Event & { context: { user: AuthUser } } {
		const user = event.context.user
		if (!user) {
			throw createError({
				statusCode: 401,
				statusMessage: "Unauthorized"
			})
		}
	}

	static assertAuthorizedUserAndId(user: AuthUser | undefined | null, id: string | undefined): asserts id is string {
		if (!user || (!id || id !== user?.id)) {
			throw createError({
				statusCode: 401,
				statusMessage: "Unauthorized"
			})
		}
	}

	encodeState(state: State): string {
		return encodeURIComponent(JSON.stringify(state))
	}

	decodeState(state: string): State {
		try {
			return zState.parse(JSON.parse(decodeURIComponent(state)))
		} catch (e) {
			this.logger.error({
				ns: "auth:decodeState",
				redact: {
					state,
					error: e
				}
			})
			throw createError({
				status: 500,
				statusMessage: "Failed to decode state.",
				data: { code: AUTH_ERROR.INTERNAL_ERROR },
			})
		}
	}


	async handleOAuth2(
		event: H3Event,
		provider: ProviderHandler<"oauth2">,
		redirectToLogin: Record<string, string>
	): Promise<{
			tokens: OAuth2Tokens
			additionalState: any
			deeplink: string | undefined
		}> {
		const query = await getValidatedQuery(event,oauth2CallbackQuery.parse)
		const state = this.decodeState(query.state)
		const storedState = getCookie(event, `${provider.name}_oauth_state`)
		const valid = !!storedState && state.oauthState === storedState
		const	tokens = valid && await provider.provider.validateAuthorizationCode(query.code)
			.catch((e: any) => e)

		await this.handleMaybeTokenError(valid, tokens, redirectToLogin)
		return {
			tokens,
			additionalState: state.additionalState,
			deeplink: state.deeplink
		}
	}

	// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
	async handleOAuth2Pcke(
		event: H3Event,
		provider: ProviderHandler<"oauth2_pcke">,
		redirectToLogin: Record<string, string>
	) {
		const query = await getValidatedQuery(event,oauth2CallbackQuery.parse)
		const state = this.decodeState(query.state)
		const storedState = getCookie(event,`${provider.name}_oauth_state`)
		const storedCodeVerifier = getCookie(event,`${provider.name}_oauth_code_verifier`)
		const valid = !!query.code && !!storedState && !!storedCodeVerifier && state.oauthState === storedState

		const tokens = valid && await provider.provider.validateAuthorizationCode(query.code, storedCodeVerifier)
			.catch((e: any) => e)
		await this.handleMaybeTokenError(valid, tokens, redirectToLogin)
		return {
			tokens,
			additionalState: state.additionalState,
			deeplink: state.deeplink
		}
	}

	// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
	async handleMaybeTokenError(valid: boolean, tokens: OAuth2Tokens | OAuth2RequestError, redirectToLogin: Record<string, string> = {}) {
		if (!valid || typeof tokens !== "object") {
			this.logger.error({
				ns: "auth:callback:oauth2RequestError",
				redact: {
					tokens,
					valid,
				}
			})
			throw createError({
				status: 400,
				statusMessage: "Invalid auth callback.",
				data: { ...redirectToLogin, code: AUTH_ERROR.INVALID_AUTH_CALLBACK },
			})
		}
	}


	async createSession(
		event: H3Event,
		sessionUserId: string,
	): Promise<{ session: AuthSession, token: string }> {
		const token = this.sessionManager.generateSessionToken()
		const session = await this.sessionManager.createSession(token, sessionUserId)

		const sessionCookie = this.sessionManager.createSessionCookie(token)
		this.logger.debug({
			ns: "auth:createSession",
			redact: {
				sessionCookie,
				sessionUserId,
			}
		})
		setCookie(event, sessionCookie.name, sessionCookie.value, sessionCookie.attributes)
		setCookie(event, `userId`, sessionUserId, sessionCookie.attributes)
		return { session, token }
	}

	// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
	async createRedirect(
		event: H3Event,
		userId: string,
		isRegistered: boolean,
		additionalState?: any,
		deeplink?: string
	) {
		let redirect = isRegistered
			? rc.public.auth.authRoutes.postRegisteredLogin
			: rc.public.auth.authRoutes.register

		const modified = this.modifyCallbackRedirect?.(
			event,
			redirect,
			userId,
			isRegistered,
			additionalState,
			deeplink
		)
		redirect = modified ?? redirect

		// see modifyCallbackRedirect note on redirectUrl param
		if (!modified) {
			redirect = this.getRedirect(
				redirect,
				isRegistered,
				deeplink,
				await this.createAccessToken(userId)
			)
		}

		this.logger.debug({
			ns: "auth:callback:createdSessionAndRedirecting",
			modified,
			deeplink,
			redirect,
			isRegistered,
			redact: { additionalState }
		})

		return sendRedirect(event, redirect)
	}

	getRedirect(
		route: string,
		isRegistered: boolean,
		deeplink: string | undefined,
		accessToken: string,
	): string {
		if (!deeplink) return route

		if (!isRegistered) {
			return `${route}?${new URLSearchParams({ deeplink }).toString()}`
		}

		const deeplinkUri = `${this.getDeeplinkScheme(deeplink)}?${new URLSearchParams({
			// eslint-disable-next-line camelcase
			access_token: accessToken,
		})}`

		return `${rc.public.auth.authRoutes.externalCode}?${new URLSearchParams({
			// eslint-disable-next-line camelcase
			access_token: accessToken,
			deeplinkUri,
		}).toString()}`
	}

	getDeeplinkScheme(deeplink: string): string { const scheme = this.deeplinkSchemes[deeplink]
		if (!scheme) {throw createError({
			status: 500,
			statusMessage: `Invalid deeplink ${deeplink}. Please specify the "deeplinkSchemes" option when creating the auth handler.`,
			data: { code: AUTH_ERROR.INVALID_DEEPLINK },
		})}
		return `${scheme}${rc.public.auth.authRoutes.deeplink}`
	}

	async verifyAccessToken(accessToken?: string): Promise<JwtPayload & { userId: string }> {
		return jwtVerify<JwtPayload & { userId: string }>(accessToken, rc.authSecret, {})
			.catch(err => {
				throw createError({
					status: 400,
					statusMessage: err.message,
					data: { code: AUTH_ERROR.INVALID_ACCESS_TOKEN },
				})
			})
	}

	async createAccessToken(userId: string, payload: Record<string, any> = {}): Promise<string> {
		return signJwt({ ...payload, userId }, rc.authSecret, {
			expiresIn: this.externalAccessTokenExpiresIn,
		})
	}
}
