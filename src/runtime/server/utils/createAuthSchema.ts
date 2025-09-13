// esm in drizzle is borked
// careful, this file can't use nuxt paths
// drizzle must be able to import it alone
import { boolean, jsonb, type PgColumn, pgTable, type PgTableWithColumns, primaryKey, text, timestamp, uuid } from "drizzle-orm/pg-core"
import { relations } from "drizzle-orm/relations"

import type { AdditionalAccountInfo } from "../../types.js"

export const authUserFields = {
	email: text("email").notNull().unique(),
	isRegistered: boolean("isRegistered").default(false).notNull()
}

export type AuthUserFields = {
	id: string
	email: string
	isRegistered: boolean
}

export function createAuthSchema(users: AuthUsersTable) {
	const authSessions = pgTable("authSessions", {
		id: text("id").primaryKey(),
		userId: uuid("userId")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		expiresAt: timestamp("expiresAt", {
			mode: "date"
		}).notNull()
	})

	const authSessionRelations = relations(authSessions, ({ one }) => ({
		user: one(users, {
			fields: [authSessions.userId],
			references: [users.id]
		})
	}))

	const authAccounts = pgTable("authAccounts", {
	// we can't be sure the email won't be changed
		providerId: text("providerId").notNull(),
		userId: uuid("userId")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		provider: text("provider").notNull(),
		name: text("name").notNull(),
		info: jsonb("info").default({}).$type<AdditionalAccountInfo>()
	}, t => ({
		id: primaryKey({ columns: [t.provider, t.providerId] })
	}))
	const authProvidersRelations = relations(authAccounts, ({ one }) => ({
		user: one(users, {
			fields: [authAccounts.userId],
			references: [users.id]
		})
	}))
	return {
		authSessions,
		authSessionRelations,
		authAccounts,
		authProvidersRelations
	}
}

export type AuthAccountsTable = ReturnType<typeof createAuthSchema>["authAccounts"]
export type AuthSessionsTable = ReturnType<typeof createAuthSchema>["authSessions"]
export type AuthSessionRelations = ReturnType<typeof createAuthSchema>["authSessionRelations"]
export type AuthProvidersRelations = ReturnType<typeof createAuthSchema>["authProvidersRelations"]

export type AuthAccount = ReturnType<typeof createAuthSchema>["authAccounts"]["$inferSelect"]
export type AuthSession = ReturnType<typeof createAuthSchema>["authSessions"]["$inferSelect"]

type BaseColumn = {
	name: any
	tableName: any
	dataType: any
	columnType: any
	driverParam: any
	hasDefault: boolean
	enumValues: any
	baseColumn: any
	isPrimaryKey: any
	isAutoincrement: any
	hasRuntimeDefault: any
	generated: any
}
export type UserTable = PgTableWithColumns<{
	dialect: "pg"
	schema: any
	name: any
	columns: {
		id: PgColumn<{
			notNull: true
			hasDefault: boolean
			dataType: "string"
			data: string
		} & Omit<BaseColumn, "hasDefault">>
		username: PgColumn<{
			notNull: false
			hasDefault: false
			dataType: "string"
			data: string
		} & Omit<BaseColumn, "username">>
		email: PgColumn<{
			notNull: true
			dataType: "string"
			data: string
		} & BaseColumn>
		isRegistered: PgColumn<{
			notNull: true
			dataType: "boolean"
			data: boolean
			hasDefault: true
		} & Omit<BaseColumn, "hasDefault">>
	}
}>

export type AuthUsersTable = PgTableWithColumns<{
	dialect: "pg"
	columns: {
		id: PgColumn<{
			name: any
			tableName: any
			dataType: any
			columnType: any
			data: string
			driverParam: any
			notNull: true
			hasDefault: boolean
			enumValues: any
			baseColumn: any
			isPrimaryKey: any
			isAutoincrement: any
			hasRuntimeDefault: any
			generated: any
		}, object>
	}
	schema: any
	name: any
}>
