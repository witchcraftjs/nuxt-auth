import type { EnumLike } from "@alanscodelog/utils"
import { enumFromArray } from "@alanscodelog/utils/enumFromArray"
import type { OAuth2Tokens } from "arctic"
import type { H3Event, Router } from "h3"
import type { StringValue } from "ms"
import type { InjectionKey } from "vue"
import { z } from "zod"

import type { GithubUser } from "./core/providers/github.js"
import type { GoogleUser } from "./core/providers/google.js"
import type {
	AuthAccount,
	AuthSession as DbAuthSession,
	AuthUserFields as DbAuthUser
} from "./server/utils/createAuthSchema.js"

import type { ModulePublicRuntimeConfig } from "../module.js"

export type * from "./server/utils/createAuthSchema.js"

/**
	* This is the minimum information providers need to return.
	*
	* It is standardized out across all providers since they all use different fields for this.
	*
	* @internal
	*/
export type InitialAccountInfo = {
	providerId: string
	email: string
	isVerified: boolean
}

/** @internal */
export type ProviderHandlerClass<TProviderName extends ProviderNames = ProviderNames> = new (
	providerOptions: ProviderHandlerOptions,
	options?: Partial<ProviderOptions<TProviderName>>
) => ProviderHandler<any, TProviderName, any>

/** @internal */
export type ProviderHandlerOptions = {
	clientId: string
	clientSecret: string
	redirectUri: string
}

// arctic no longer exports these, and the code has been rewritten not to depend on them as much
// but we still use them to check the TProvider type
// eslint-disable-next-line @typescript-eslint/naming-convention
interface OAuth2Provider {
	createAuthorizationURL(state: string, scopes: string[]): URL
	validateAuthorizationCode(code: string): Promise<OAuth2Tokens>
	refreshAccessToken?(refreshToken: string): Promise<OAuth2Tokens>
}
// eslint-disable-next-line @typescript-eslint/naming-convention
interface OAuth2ProviderWithPKCE {
	createAuthorizationURL(state: string, codeVerifier: string, scopes: string[]): URL
	validateAuthorizationCode(code: string, codeVerifier: string): Promise<OAuth2Tokens>
	refreshAccessToken?(refreshToken: string): Promise<OAuth2Tokens>
}

export interface ProviderHandler<
	TType extends "oauth2" | "oauth2_pcke" = "oauth2" | "oauth2_pcke",
	TProviderName extends ProviderNames = ProviderNames,
	TProvider extends
	TType extends "oauth2" ? OAuth2Provider : TType extends "oauth2_pcke" ? OAuth2ProviderWithPKCE : never = TType extends "oauth2" ? OAuth2Provider : TType extends "oauth2_pcke" ? OAuth2ProviderWithPKCE : never
> {
	provider: TProvider
	type: TType
	name: TProviderName
	getAccountInfo: (tokens: OAuth2Tokens) => Promise<Omit<BaseProviderAccountInfo, "userId">>
	getLoginInfo: (state: string) =>
	TType extends "oauth2"
		? OAuth2AuthUrl
		: TType extends "oauth2_pcke"
			? OAuth2PkceAuthUrl
			: never

}

// eslint-disable-next-line @typescript-eslint/naming-convention
export type OAuth2AuthUrl = {
	type: "oauth2"
	url: URL
}
// eslint-disable-next-line @typescript-eslint/naming-convention
export type OAuth2PkceAuthUrl = {
	type: "oauth2_pcke"
	url: URL
	codeVerifier: string
}

export interface Register {
}

// am having issues doing this via declaration merging :/
export interface InternalProviders {
	// google: GoogleUser
	// github: GithubUser
}

type InternalProviderObject = {
	[k in keyof InternalProviders]: InternalProviders[k]
}

// eslint-disable-next-line @typescript-eslint/naming-convention
type AdditionalProviders = Register extends { AdditionalProviders: infer T }
	? T extends Record<string, any>
		? T
		: never
	: never

// eslint-disable-next-line @typescript-eslint/naming-convention
export type AdditionalAccountInfo = Register extends { AdditionalAccountInfo: infer T } ? T : never

// eslint-disable-next-line @typescript-eslint/naming-convention
export type AdditionalApiRoutes = (Register extends { ApiRoutes: infer T }
	? T extends Record<string, any>
		? T
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		: {}
	// eslint-disable-next-line @typescript-eslint/no-empty-object-type
	: {})

// eslint-disable-next-line @typescript-eslint/naming-convention
export type ApiRoutesParams = (Register extends { ApiRoutesParams: infer T }
	? T extends Record<string, any>
		? T
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		: {}
	// eslint-disable-next-line @typescript-eslint/no-empty-object-type
	: {}) & {
		userIdAccounts: Record<"id", string>
		login: Record<"provider", string>
		callback: Record<"provider", string>
		usernameValid: Record<"username", string>
	}

// eslint-disable-next-line @typescript-eslint/naming-convention
export type AuthSession = (Register extends { AuthSession: infer T }
	? T extends Record<string, any>
		? T
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		: {}
	// eslint-disable-next-line @typescript-eslint/no-empty-object-type
	: {}) & DbAuthSession

// eslint-disable-next-line @typescript-eslint/naming-convention
export type AuthUser = (Register extends { AuthUser: infer T }
	? T extends Record<string, any>
		? T
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		: {}
	// eslint-disable-next-line @typescript-eslint/no-empty-object-type
	: {}) & DbAuthUser

export type SessionValidationResult
	= | { session: AuthSession, user: AuthUser, fresh: boolean }
		| { session: null, user: null, fresh: false }

export type SessionCookieOptions = {
	secure?: boolean
	path?: string
	domain?: string
	sameSite?: "lax" | "strict" | "none"
	httpOnly?: boolean
	maxAge?: number
	expires?: Date
}

export type SessionCookie = {
	name: string
	value: string
	attributes: SessionCookieOptions
}

export type ProviderAccountInfo = InternalProviderObject | AdditionalProviders

export type MockUser = Partial<Omit<BaseProviderAccountInfo, "userId">>

export type ProviderOptions<
	TProviderName extends ProviderNames = ProviderNames,
	TProviderAccountInfo extends ProviderAccountInfo[TProviderName] = ProviderAccountInfo[TProviderName]
> = {
	/**
	 * This determines what additional account information the provider should return and save to the *accounts* table under the `info` field.
	 *
	 * For example, say you also wanted to return the user's avatar to populate a user with on registration.
	 *
	 * Each provider defines it in a different way, so you'd need to specify this function for each provider you're interested in.
	 *
	 * You can type the return by declaration merging with the `AuthExtendedUserInfo` interface.
	 *
	 * This is set only once per provider account creation and can the info column can just be cleared after the information is no longer needed.
	 */
	getAdditionalAccountInfo?: (user: TProviderAccountInfo) => Promise<AdditionalAccountInfo>
}

export type AuthOptions = {
	/** The base url for the site (e.g. http:/localhost:3000 during dev), required for the redirectUri. */
	baseUrl?: string
	runtimeConfig: ModulePublicRuntimeConfig
	handlers: {
		[k in ProviderNames]: ProviderHandlerClass<k>
	}
	enabledProviders: ProviderNames[]
} & Partial<Omit<AuthHandlerOptions, "customProviders">>

export type AuthHandlerOptions<T = any> = {

	/**
	 * For the short lived access tokens used for external logins.
	 *
	 * Uses vercel/ms package to parse durations.
	 *
	 * @default 10m
	 */
	externalAccessTokenExpiresIn?: StringValue

	/**
		* Modify the callback redirect url AFTER the provider has redirected to the app and an account has been created / user has been logged in.
		*
		* Useful, to, fore example, redirect instead to a special schema / deep link (e.g. from the browser to a desktop app).
		*/
	modifyCallbackRedirect: (
		event: H3Event,
		/** The url here does not yet have the deeplink query param. This is because it's relative and can get complicated to parse. So it's added afterwards, only if the link wasn't modified. */
		redirectUrl: string,
		userId: string,
		isRegistered: boolean,
		additionalState: T,
		deeplink?: string
	) => string | undefined

	/**
	 * Store additional state in the callback url.
	 *
	 * Is later available in the `modifyCallbackRedirect` option.
	 */
	additionalState?: (event: H3Event) => T
	customProviders?: {
		[k in ProviderNames]: ProviderHandlerClass<k>
	}
	providerOptions?: {
		[k in ProviderNames]: ProviderOptions<k>
	}
	baseUrl: string
	/**
	 * Is called on user registration. User is guaranteed to be authenticated and not already registered.
	 *
	 * Return something and it will be returned as the response.
	 *
	 * If you return `false` or `undefined`, the handler will redirect to `authRoutes.postRegisteredLogin`.
	 */
	onRegister?: (event: H3Event) => Promise<any>
	/**
	 * Extend the router with your own routes.
	 *
	 * This is useful for adding custom endpoints like `/api/auth/public/users/:username/valid`.
	 */
	extendRouter?: (router: Router) => void
	// todo readme link
	/**
	 * A mapping of deeplink type to a scheme (e.g. electron => `app-name-electron:`).
	 *
	 * This is used to generate the redirect url for the external auth handler, see the readme for more info.
	 */
	deeplinkSchemes?: Record<string, string>
	devBypassAuth?: boolean
	/**
	 * When bypassing auth, this function is called to create the mock user info. Note that it's called whether the user exists or not. If seeding you database with test users, you should attempt to fetch any existing users here.
	 *
	 * Any missing fields will be filled in with the defualt generator. Same thing if you return undefined.
	 */
	createMockUser?: (username: string | undefined, id: string | undefined, provider: string) => MockUser | Promise<MockUser> | undefined | Promise<undefined>
	/** Should return any additional fields non-nullable fields without defaults that are needed to be able to add a user. */
	generateUser?: () => any
}

/**
	* A zod username schema to use for validating usernames.
	*/
export const defaultZodUsernameSchema = z.string()
	.min(3)
	.max(32)
	.regex(/^[\w.]+$/, "Username can only contain letters, numbers, underscores, and periods.")

export type ProviderNames = keyof InternalProviders | (AdditionalProviders extends never ? never : keyof AdditionalProviders)

export type Secrets = Partial<
	Record<`auth${Capitalize<ProviderNames>}ClientId`, string>
	& Record<`auth${Capitalize<ProviderNames>}ClientSecret`, string>
>

export interface BaseProviderAccountInfo extends AuthAccount, InitialAccountInfo {

}

export type ProviderStyle = {
	name: string
	logo: any
	style: {
		bg: string
		text: string
		bgDark: string
		textDark: string
	}
}

export const providerStylesInjectionKey = Symbol("providerStyles") as InjectionKey<Partial<Record<ProviderNames, Partial<ProviderStyle>>>>

export type FullProviderStyles = Record<"github" | "google", ProviderStyle> & Record<ProviderNames, Partial<ProviderStyle>>

export type UseAuthComposableOptions = {
	/**
	 * Handle login and logout actions yourself.
	 *
	 * Return `true` to let prevent the handler from handling the action.
	 */
	handleActions?: ActionHandler
}
/**
 * See {@link UseAuthComposableOptions.handleActions}
 */
export type ActionHandler
	= ((action: "login", url: string, provider: ProviderNames) => any | false)
		& ((action: "logout", url: string) => any | false)

export const AUTH_ERROR = enumFromArray([
	"USER_ALREADY_REGISTERED",
	"UNKNOWN_PROVIDER",
	"ACCOUNT_ALREADY_LINKED",
	"FAILED_TO_ADD_PROVIDER_ACCOUNT",
	"FAILED_TO_CREATE_USER",
	"INVALID_AUTH_CALLBACK",
	"INTERNAL_ERROR",
	"INVALID_DEEPLINK",
	"INVALID_ACCESS_TOKEN"
], "AUTH.")

export type AuthError = EnumLike<typeof AUTH_ERROR>
