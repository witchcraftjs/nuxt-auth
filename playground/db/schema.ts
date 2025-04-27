// careful, we can't use nuxt paths or .js file endings because of drizzle
import { authUserFields, createAuthSchema } from "@witchcraft/nuxt-auth/createAuthSchema.js"
import { sql } from "drizzle-orm"
import {
	pgTable,
	uuid,
	varchar,
} from "drizzle-orm/pg-core"


export const users = pgTable("users", {
	id: uuid("id").primaryKey().unique()
		.notNull()
		.default(sql`gen_random_uuid()`),
	username: varchar("username", { length: 256 }).unique(),
	...authUserFields,
})

const auth = createAuthSchema(users)
export const authAccounts = auth.authAccounts
export const authSessions = auth.authSessions
export const authProviderRelations = auth.authProvidersRelations
export const authSessionRelations = auth.authSessionRelations

