import { capitalize } from "@alanscodelog/utils/capitalize"
import type { StandardSchemaV1 } from "@standard-schema/spec"
import { betterAuth, type BetterAuthOptions } from "better-auth"
import { drizzleAdapter } from "better-auth/adapters/drizzle"
import { createAuthEndpoint } from "better-auth/api"
import { username } from "better-auth/plugins"
import { defuArrayFn } from "defu"
import { z } from "zod"

import type { AuthAccountsTable, AuthSessionsTable, AuthUsersTable, AuthVerificationsTable } from "./createAuthSchema.js"
import { registerAuthInstance } from "./getBetterAuthInstance.js"

import { useRuntimeConfig } from "#imports"

import { devMock } from "../../plugins/server/devMock.js"

const MIN_AUTH_SECRET_BYTES = 32

export function createBetterAuth({
	appUrl = useRuntimeConfig().public?.auth?.publicServerUrl,
	db,
	schema,
	usernameSchema,
	minUsernameLength,
	maxUsernameLength,
	mockTransferCodeTtlMs,
	generateUser,
	betterAuthOptions,
	logger
}: {
	db: any
	schema: {
		users: AuthUsersTable
		authAccounts: AuthAccountsTable
		authSessions: AuthSessionsTable
		authVerifications: AuthVerificationsTable
	}
	/** App url, defaults to the runtime config `auth.publicServerUrl`. */
	appUrl?: string
	/** The username schema, used to validate usernames ON TOP of better-auth's limits. Note that if you change min/max length you *also* need to change minUsernameLength and maxUsernameLength (which are passed on to better-auth) or you will run into problems. */
	usernameSchema: StandardSchemaV1<string, string>
	/** Shortest allowed username, passed to better-auth. */
	minUsernameLength?: number
	/** Longest allowed username, passed to better-auth. */
	maxUsernameLength?: number
	/** How long a dev-mock transfer code stays valid, defaults to 5 minutes. */
	mockTransferCodeTtlMs?: number
	/**
	 * Escape hatch, deep-merged (via defuArrayFn) over the module defaults.
	 * Use it to add better-auth plugins, hooks, or extra options.
	 * Replacing a block the module sets (e.g. `databaseHooks.user.update.before`)
	 * replaces the module behavior for that block. Array values (e.g. `plugins`)
	 * concatenate by default, pass a function receiving the defaults to take
	 * full control over them.
	 */
	betterAuthOptions?: BetterAuthOptions
	generateUser?: (() => any)
	/** Optional logger, used for warnings such as providers skipped for missing secrets. */
	logger?: any
}) {
	const usernameValidator = async (username: string) => {
		try {
			return !("issues" in await usernameSchema["~standard"].validate(username))
		} catch {
			return false
		}
	}

	const rc = useRuntimeConfig() as any

	const authRoutes = rc.public?.auth?.authRoutes

	const providersFromConfig: Record<string, { clientId: string, clientSecret: string }> = {}
	for (const name of rc.public?.auth?.enabledProviders ?? []) {
		const clientId = rc[`auth${capitalize(name)}ClientId`]
		const clientSecret = rc[`auth${capitalize(name)}ClientSecret`]
		if (clientId && clientSecret) {
			providersFromConfig[name] = { clientId, clientSecret }
		} else {
			logger?.warn({
				ns: "auth:init:missingSecrets",
				error: `Missing auth${capitalize(name)}ClientId or auth${capitalize(name)}ClientSecret for ${name}. Disabling.`
			})
		}
	}

	const socialProviders: Record<string, { clientId: string, clientSecret: string }> = {}
	for (const [name, cfg] of Object.entries(providersFromConfig)) {
		socialProviders[name] = { clientId: cfg.clientId, clientSecret: cfg.clientSecret }
	}

	const authSecretValue = rc.authSecret || ""

	// better-auth does not check at init and not to this level, and mentions it's secret env variable instead of ours
	if (!authSecretValue) {
		throw new Error("FATAL: Missing or empty runtimeConfig.authSecret (i.e. should be set via NUXT_AUTH_SECRET) in production.")
	}
	if (Buffer.byteLength(authSecretValue, "utf8") < MIN_AUTH_SECRET_BYTES) {
		throw new Error(`FATAL: runtimeConfig.authSecret must be at least ${MIN_AUTH_SECRET_BYTES} bytes (e.g. \`openssl rand -base64 32\`) in production.`)
	}

	const plugins: any[] = [
		username({
			minUsernameLength: minUsernameLength,
			maxUsernameLength: maxUsernameLength,
			usernameValidator,
			usernameNormalization: false,
			displayUsername: false,
			immutableUsername: false
		}),
		{
			/**
			 * Thin GET wrapper over Better Auth's `POST /is-username-available`.
			 *
			 * Unlike better-auth returns a boolean to make client side usage easier with the useAsyncValidation composable.
			 *
			 * Added as an extension of better-auth's handler so it's always under the configured catch-all base path.
			 */
			id: "username-valid",
			endpoints: {
				usernameValid: createAuthEndpoint("/username/valid", {
					method: "GET",
					query: z.object({ username: z.string() })
				}, async ctx => {
					try {
						if (!await usernameValidator(ctx.query.username)) return false
						const existing = await ctx.context.adapter.findOne({
							model: "user",
							where: [{ field: "username", value: ctx.query.username }]
						})
						return !existing
					} catch {
						return false
					}
				})
			}
		}
	]

	if (rc.public?.auth?.devBypassAuth && import.meta.dev) {
		plugins.push(devMock({
			generateUser,
			authRoutes,
			enabledProviders: rc.public?.auth?.enabledProviders ?? [],
			usernameValidator,
			maxUsernameLength,
			transferCodeTtlMs: mockTransferCodeTtlMs
		}))
	}

	const auth = betterAuth(defuArrayFn(betterAuthOptions ?? {}, {
		database: drizzleAdapter(db, {
			provider: "pg",
			camelCase: true,
			schema: {
				user: schema.users,
				account: schema.authAccounts,
				session: schema.authSessions,
				verification: schema.authVerifications
			}
		}),
		secret: authSecretValue || undefined,
		baseURL: appUrl,
		trustedOrigins: [appUrl],
		logger: logger
			? {
					log: (level: string, message: string, ...args: any[]) => {
						const method = level === "success" ? "info" : level
						logger[method]?.({ ns: "auth:better-auth", message, args })
					}
				}
			: undefined,
		advanced: {
			cookiePrefix: rc.public.auth.cookiePrefix,
			// better-auth skips this check whenever it detects a test run, which hides
			// rejected origins in tests, so it is forced on here
			disableOriginCheck: false,
			database: { generateId: () => crypto.randomUUID() },
			cookies: {
				session_token: {
					attributes: { ...(rc.public?.auth?.sessionCookieOpts ?? {}) }
				}
			}
		},
		session: { expiresIn: rc.public.auth.sessionExpiresAt / 1000 },
		socialProviders,
		emailAndPassword: { enabled: false },
		user: {
			additionalFields: {
				isRegistered: { type: "boolean", defaultValue: false, input: false, returned: true }
			}
		},
		databaseHooks: {
			user: {
				update: {
					before: async (user: any) => {
						if (user && "username" in user && user.username) {
							return { data: { ...user, isRegistered: true } }
						}
						return
					}
				}
			}
		},
		plugins
	}) as BetterAuthOptions)
	registerAuthInstance(auth)
	return auth
}
