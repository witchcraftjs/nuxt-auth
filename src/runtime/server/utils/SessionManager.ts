import type { DeepPartial } from "@alanscodelog/utils"
import { sha256 } from "@oslojs/crypto/sha2"
import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from "@oslojs/encoding"
import { eq } from "drizzle-orm"
import type { PgDatabase } from "drizzle-orm/pg-core"
import type { RuntimeConfig } from "nuxt/schema"

import type {
	AuthSessionsTable,
	AuthUsersTable
} from "./createAuthSchema.js"

import type {
	AuthSession,
	SessionCookie,
	SessionCookieOptions,
	SessionValidationResult
} from "../../types.js"

export const defaultSessionCookieName = "authSession"

export class SessionManager {
	options: {
		expiresAt: number
		sessionCookie: {
			name: string
			attributes: Omit<SessionCookieOptions, "maxAge">
		}
	}

	db: PgDatabase<any, any, any>

	sessionTable: AuthSessionsTable

	userTable: AuthUsersTable

	constructor(
		rc: RuntimeConfig,
		db: SessionManager["db"],
		sessionTable: SessionManager["sessionTable"],
		userTable: SessionManager["userTable"],
		options: DeepPartial<SessionManager["options"]> = {}
	) {
		this.db = db
		this.sessionTable = sessionTable
		this.userTable = userTable
		this.options = {
			expiresAt: rc.public.auth.sessionExpiresAt,
			...options,
			sessionCookie: {
				name: defaultSessionCookieName,
				...options.sessionCookie,
				attributes: {
					secure: rc.public.auth.isSecure,
					...(rc.public.auth.sessionCookieOpts ?? {}),
					...options.sessionCookie?.attributes
				}
			}
		}
	}

	generateSessionToken(): string {
		const bytes = new Uint8Array(20)
		crypto.getRandomValues(bytes)
		const token = encodeBase32LowerCaseNoPadding(bytes)
		return token
	}

	async createSession<TId = string>(
		sessionToken: string,
		userId: TId
	): Promise<AuthSession> {
		const hashedSessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(sessionToken)))
		const session: AuthSession = {
			id: hashedSessionId,
			userId: userId as any,
			expiresAt: new Date(Date.now() + this.options.expiresAt)
		}
		await this.db.insert(this.sessionTable).values(session)
		return session
	}

	createSessionCookie(sessionId: string): SessionCookie {
		return {
			name: this.options.sessionCookie.name,
			value: sessionId,
			attributes: {
				...this.options.sessionCookie.attributes,
				maxAge: new Date().getTime() + this.options.expiresAt
			}
		}
	}

	createBlankSessionCookie(): SessionCookie {
		return {
			name: this.options.sessionCookie.name,
			value: "",
			attributes: {
				...this.options.sessionCookie.attributes,
				maxAge: 0
			}
		}
	}

	async validateSessionToken(sessionToken: string): Promise<SessionValidationResult> {
		const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(sessionToken)))
		const result = await this.db
			.select({ user: this.userTable, session: this.sessionTable })
			.from(this.sessionTable)
			.innerJoin(this.userTable, eq(this.sessionTable.userId, this.userTable.id))
			.where(eq(this.sessionTable.id, sessionId))

		if (result.length < 1) {
			return { session: null, user: null, fresh: false }
		}

		const { user, session } = result[0]!

		const expired = Date.now() >= session.expiresAt.getTime()
		if (expired) {
			await this.db.delete(this.sessionTable).where(eq(this.sessionTable.id, session.id))
			return { session: null, user: null, fresh: false }
		}

		const canBeExtended = Date.now() >= session.expiresAt.getTime() - (this.options.expiresAt / 2)

		if (canBeExtended) {
			session.expiresAt = new Date(Date.now() + this.options.expiresAt)
			await this.db
				.update(this.sessionTable)
				.set({
					expiresAt: session.expiresAt
				})
				.where(eq(this.sessionTable.id, session.id))
		}

		return {
			session,
			user: user as any, // cast because it contains extra attributes
			fresh: canBeExtended
		}
	}

	async invalidateSession(sessionId: string): Promise<void> {
		await this.db.delete(this.sessionTable)
			.where(eq(this.sessionTable.id, sessionId))
	}
}
