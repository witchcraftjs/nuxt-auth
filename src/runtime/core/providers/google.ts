import GoogleLogo from "~icons/logos/google-icon"

// https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload
export interface GoogleUser {
	/* eslint-disable @typescript-eslint/naming-convention */
/** The audience (your app's client ID). */
	aud: string
	/** Expiration time in Unix time (seconds). */
	exp: number
	/** Issued at time in Unix time (seconds). */
	iat: number
	/** Issuer Identifier (always "https://accounts.google.com"). */
	iss: string
	/** User identifier, unique across Google accounts. */
	sub: string
	/** Optional: Access token hash for validation. */
	at_hash?: string
	/** Optional: Authorized presenter client ID (hybrid apps). */
	azp?: string
	email: string
	email_verified: boolean
	family_name?: string
	given_name?: string
	/**  User's Google Workspace/Cloud domain. */
	hd?: string
	/**  User's locale. */
	locale?: string
	/**  User's full name. */
	name?: string
	/**  Nonce value for replay attack protection. */
	nonce?: string
	/**  URL of user's profile picture. */
	picture?: string
	/**  URL of user's profile page. */
	profile?: string
/* eslint-enable @typescript-eslint/naming-convention */
}


import {
	generateCodeVerifier,
	Google,
	type OAuth2Tokens
} from "arctic"

import type { BaseProviderAccountInfo, ProviderHandler, ProviderHandlerOptions, ProviderOptions } from "../../types"

declare module "../../types.js" {
	interface InternalProviders {
		google: GoogleUser
	}
}
export default class GoogleProvider implements ProviderHandler<"oauth2_pcke", "google", Google> {
	name = "google" as const

	type = "oauth2_pcke" as const

	provider: Google

	providerOptions: ProviderHandlerOptions

	options: Partial<ProviderOptions<"google">>

	constructor(
		providerOptions: GoogleProvider["providerOptions"],
		options: GoogleProvider["options"] = {}
	) {
		this.providerOptions = providerOptions
		this.options = options
		this.provider = new Google(
			providerOptions.clientId,
			providerOptions.clientSecret,
			providerOptions.redirectUri
		)
	}

	// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
	getLoginInfo(state: string) {
		const codeVerifier = generateCodeVerifier()
		const url = this.provider.createAuthorizationURL(state, codeVerifier, ["profile", "email"],)

		return { type: "oauth2_pcke" as const, url, codeVerifier }
	}

	// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
	async getAccountInfo(tokens: OAuth2Tokens) {
		const user = await $fetch<any>("https://openidconnect.googleapis.com/v1/userinfo", {
			headers: {
				Authorization: `Bearer ${tokens.accessToken()}`
			}
		}) as GoogleUser

		const baseInfo: Omit<BaseProviderAccountInfo, "userId" | "info"> = {
			providerId: user.sub.toString(),
			provider: "google",
			name: user.name ?? "",
			email: user.email,
			isVerified: user.email_verified
		}
		return {
			...baseInfo,
			info: (await this.options.getAdditionalAccountInfo?.(user)) ?? null,
		}
	}
}
export const googleProviderStyle = {
	name: "Google",
	logo: GoogleLogo,
	style: {
		bg: "#fff",
		bgDark: "#000",
		text: "#000",
		textDark: "#fff"
	},
}

