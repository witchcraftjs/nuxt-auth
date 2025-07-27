import type { PgDatabase } from "drizzle-orm/pg-core"
import type { EventHandler } from "h3"

import { Auth } from "./Auth.js"
import type { AuthAccountsTable,UserTable } from "./createAuthSchema.js"
import { type SessionManager } from "./SessionManager.js"

import github from "#auth/core/providers/github.js"
import google from "#auth/core/providers/google.js"
import {
	createRouter,
	useRuntimeConfig,
	useServerLogger,
} from "#imports"

import type { AuthHandlerOptions } from "../../types.js"

export function createAuthHandler(
	db: PgDatabase<any, any, any>,
	usersTable: UserTable,
	authAccountsTable: AuthAccountsTable,
	sessionManager: SessionManager,
	opts: Partial<AuthHandlerOptions> = {}
): EventHandler {
	const rc = useRuntimeConfig()
	const router = createRouter()
	const logger = useServerLogger()
	const auth = new Auth(
		db,
		usersTable,
		authAccountsTable,
		sessionManager,
		router,
		{
			...opts,
			enabledProviders: rc.public.auth.enabledProviders as any,
			handlers: {
				github,
				google,
				...(opts.customProviders ?? {}),
			}
		},
		rc as any,
		logger
	)
	return auth.eventHandler
}
