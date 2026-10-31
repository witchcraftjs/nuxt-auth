// esm in drizzle is borked
// careful, this file can't use nuxt paths
// drizzle must be able to import it alone
import { boolean, type PgColumnBuilderBase, pgTable, type PgTableWithColumns, text, timestamp, uuid } from "drizzle-orm/pg-core"
import { relations } from "drizzle-orm/relations"

/**
 * Coopy of the better-auth user shape + username and isRegistered.
 *
 * Core fields match https://www.better-auth.com/docs/concepts/database#user
 *
 * `username` matches the username plugin schema https://www.better-auth.com/docs/plugins/username#schema
 *
 * `isRegistered` is this module's own field, set through better-auth's `user.additionalFields`.
 */
export const authUserFields = {
	id: uuid("id").primaryKey(),
	email: text("email").notNull().unique(),
	emailVerified: boolean("emailVerified").default(false).notNull(),
	name: text("name").notNull(),
	image: text("image"),
	username: text("username").unique(),
	isRegistered: boolean("isRegistered").default(false).notNull(),
	createdAt: timestamp("createdAt", { mode: "date" }).notNull().defaultNow(),
	updatedAt: timestamp("updatedAt", { mode: "date" }).notNull().defaultNow()
}

/**
 * Builds the app's `users` table from the module's fields, with any column overridable.
 * e.g. `createAuthUserSchema({ id: uuid("id").primaryKey().default(sql`gen_random_uuid()`) })`.
 */
export function createAuthUserSchema<
	T extends Partial<Record<"id" | keyof typeof authUserFields, PgColumnBuilderBase>> = Record<never, never>
>(overrides: T = {} as T) {
	return pgTable("users", {
		...authUserFields,
		...overrides
	})
}

export function createAuthSchema(users: AuthUsersTable) {
	/**
	 * App-owned copy of the better-auth session shape.
	 * https://www.better-auth.com/docs/concepts/database#session
	 */
	const authSessions = pgTable("authSessions", {
		id: text("id").primaryKey(),
		userId: uuid("userId")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		expiresAt: timestamp("expiresAt", { mode: "date" }).notNull(),
		token: text("token").notNull().unique(),
		ipAddress: text("ipAddress"),
		userAgent: text("userAgent"),
		createdAt: timestamp("createdAt", { mode: "date" }).notNull().defaultNow(),
		updatedAt: timestamp("updatedAt", { mode: "date" }).notNull().defaultNow()
	})

	const authSessionRelations = relations(authSessions, ({ one }) => ({
		user: one(users, {
			fields: [authSessions.userId],
			references: [users.id]
		})
	}))

	/**
	 * App-owned copy of the better-auth account shape.
	 * https://www.better-auth.com/docs/concepts/database#account
	 */
	const authAccounts = pgTable("authAccounts", {
		id: text("id").primaryKey(),
		accountId: text("accountId").notNull(),
		providerId: text("providerId").notNull(),
		userId: uuid("userId")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		accessToken: text("accessToken"),
		refreshToken: text("refreshToken"),
		idToken: text("idToken"),
		accessTokenExpiresAt: timestamp("accessTokenExpiresAt", { mode: "date" }),
		refreshTokenExpiresAt: timestamp("refreshTokenExpiresAt", { mode: "date" }),
		scope: text("scope"),
		password: text("password"),
		createdAt: timestamp("createdAt", { mode: "date" }).notNull().defaultNow(),
		updatedAt: timestamp("updatedAt", { mode: "date" }).notNull().defaultNow()
	})

	const authProvidersRelations = relations(authAccounts, ({ one }) => ({
		user: one(users, {
			fields: [authAccounts.userId],
			references: [users.id]
		})
	}))

	/**
	 * App-owned copy of the better-auth verification shape.
	 * https://www.better-auth.com/docs/concepts/database#verification
	 */
	const authVerifications = pgTable("authVerifications", {
		id: text("id").primaryKey(),
		identifier: text("identifier").notNull(),
		value: text("value").notNull(),
		expiresAt: timestamp("expiresAt", { mode: "date" }).notNull(),
		createdAt: timestamp("createdAt", { mode: "date" }).notNull().defaultNow(),
		updatedAt: timestamp("updatedAt", { mode: "date" }).notNull().defaultNow()
	})

	return {
		authSessions,
		authSessionRelations,
		authAccounts,
		authProvidersRelations,
		authVerifications
	}
}

export type AuthAccountsTable = ReturnType<typeof createAuthSchema>["authAccounts"]
export type AuthSessionsTable = ReturnType<typeof createAuthSchema>["authSessions"]
export type AuthSessionRelations = ReturnType<typeof createAuthSchema>["authSessionRelations"]
export type AuthProvidersRelations = ReturnType<typeof createAuthSchema>["authProvidersRelations"]
export type AuthVerificationsTable = ReturnType<typeof createAuthSchema>["authVerifications"]

export type AuthAccount = ReturnType<typeof createAuthSchema>["authAccounts"]["$inferSelect"]
export type AuthSession = ReturnType<typeof createAuthSchema>["authSessions"]["$inferSelect"]

export type AuthUsersTable = PgTableWithColumns<any>
