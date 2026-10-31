import type { Auth } from "better-auth"

let currentAuth: Auth<any> | undefined

export function registerAuthInstance(auth: Auth<any>): void {
	currentAuth = auth
}

export function useAuthInstance(): Auth<any> {
	if (!currentAuth) {
		throw new Error("Auth instance is not registered. Call createBetterAuth (e.g. by importing server/auth) before handling requests.")
	}
	return currentAuth
}
