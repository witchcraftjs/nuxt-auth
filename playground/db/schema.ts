// careful, we can't use nuxt paths or .js file endings because of drizzle
import { createAuthSchema, createAuthUserSchema } from "@witchcraft/nuxt-auth/server/utils/createAuthSchema"
import { sql } from "drizzle-orm"
import {
	uuid,
} from "drizzle-orm/pg-core"


export const users = createAuthUserSchema({
	id: uuid("id").primaryKey().unique()
		.notNull()
		.default(sql`gen_random_uuid()`),
})

const auth = createAuthSchema(users)
export const authAccounts = auth.authAccounts
export const authSessions = auth.authSessions
export const authVerifications = auth.authVerifications
export const authProviderRelations = auth.authProvidersRelations
export const authSessionRelations = auth.authSessionRelations

