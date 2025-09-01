import GithubLogo from "~icons/logos/github-icon"

declare module "../../types.js" {
	interface InternalProviders {
		github: GithubUser
	}
}

// https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28
/* eslint-disable @typescript-eslint/naming-convention */
export interface GithubUser {
	login: string
	id: number
	node_id: string
	avatar_url: string
	gravatar_id: string | null
	url: string
	html_url: string
	followers_url: string
	following_url: string
	gists_url: string
	starred_url: string
	subscriptions_url: string
	organizations_url: string
	repos_url: string
	events_url: string
	received_events_url: string
	type: string
	site_admin: boolean
	name: string | null
	company: string | null
	blog: string | null
	location: string | null
	email: string | null
	notification_email?: string | null
	hireable: boolean | null
	bio: string | null
	twitter_username?: string | null
	public_repos: number
	public_gists: number
	followers: number
	following: number
	created_at: string
	updated_at: string
	private_gists: number
	total_private_repos: number
	owned_private_repos: number
	disk_usage: number
	collaborators: number
	two_factor_authentication: boolean
	plan?: {
		collaborators: number
		name: string
		space: number
		private_repos: number
		[k: string]: unknown
	}
	suspended_at?: string | null
	business_plus?: boolean
	ldap_dn?: string
	[k: string]: unknown
}

type GithubEmails = {
	email: string
	primary: boolean
	verified: boolean
	visibility: string | null
}[]

/* eslint-enable @typescript-eslint/naming-convention */

import { unreachable } from "@alanscodelog/utils/unreachable"
import {
	GitHub,
	type OAuth2Tokens,
} from "arctic"

import type { BaseProviderAccountInfo, ProviderHandler, ProviderHandlerOptions, ProviderOptions } from "../../types"

export default class GithubProvider implements ProviderHandler<"oauth2", "github", GitHub> {
	name = "github" as const

	type = "oauth2" as const

	provider: GitHub

	providerOptions: ProviderHandlerOptions

	options: Partial<ProviderOptions<"github">>

	constructor(
		providerOptions: GithubProvider["providerOptions"],
		options: GithubProvider["options"] = {}
	) {
		this.providerOptions = providerOptions
		this.options = options

		this.provider = new GitHub(
			providerOptions.clientId,
			providerOptions.clientSecret,
			providerOptions.redirectUri
		)
	}

	// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
	getLoginInfo(state: string) {
		const url = this.provider.createAuthorizationURL(state, ["user:email"])
		return { type: "oauth2" as const, url }
	}

	// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
	async getAccountInfo(tokens: OAuth2Tokens) {
		const user = await $fetch<any>("https://api.github.com/user", {
			headers: {
				Authorization: `Bearer ${tokens.accessToken()}`
			}
		}) as GithubUser
		const emails = await $fetch<any>("https://api.github.com/user/emails", {
			headers: {
				Authorization: `Bearer ${tokens.accessToken()}`
			}
		}) as GithubEmails
		const email = emails.find(m => m.primary)

		if (!email) unreachable()
		const baseInfo: Omit<BaseProviderAccountInfo, "userId" | "info"> = {
			providerId: user.id.toString(),
			provider: "github",
			name: user.login,
			email: email.email,
			isVerified: email.verified
		}

		return {
			...baseInfo,
			info: (await this.options.getAdditionalAccountInfo?.(user)) ?? null,
		}
	}
}
export const githubProviderStyle = {
	name: "Github",
	logo: GithubLogo,
	style: {
		bg: "#fff",
		bgDark: "#000",
		text: "#000",
		textDark: "#fff"
	},
}
