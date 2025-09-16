import type { ProviderOptions } from "@witchcraft/nuxt-auth"

import type { GithubUser } from "#auth/core/providers/github.js"
import { SessionManager } from "#auth/server/utils/SessionManager.js"
import { postgres as db } from "#postgres"
import { authSessions, users } from "~~/db/schema.js"


export const sessionManager = new SessionManager(
	useRuntimeConfig(),
	db,
	authSessions,
	users,
	{
		sessionCookie: {
			attributes: {
				secure: useRuntimeConfig().public.auth.isSecure
			}
		}
	}
)

export const githubOptions: ProviderOptions<"github"> = {
	getAdditionalAccountInfo: async ({ avatar_url: avatarUrl }: GithubUser) => ({ avatarUrl })
}

declare module "@witchcraft/nuxt-auth/types" {
	interface Register {
		// eslint-disable-next-line @typescript-eslint/naming-convention
		AdditionalAccountInfo: {
			avatarUrl?: string
		}
		// eslint-disable-next-line @typescript-eslint/naming-convention
		AuthUser: {
			username?: string
		}
	}
}
