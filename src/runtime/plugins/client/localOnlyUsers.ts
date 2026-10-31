import { jsonSafeParse } from "@alanscodelog/utils/jsonSafeParse"
import type { StandardSchemaV1 } from "@standard-schema/spec"

import { useState } from "#app"

import type { AuthUser, AuthUserStored } from "../../types.js"
import { localOnlyUsersStorageKey, userStorageKey } from "../../types.js"
import { deserializeAuthLocalUser } from "../../utils/deserializeAuthLocalUser.js"


export function localOnlyUsers({
	storageKey = localOnlyUsersStorageKey,
	userSchema
}: {
	storageKey?: string
	/** Validates each stored user, e.g. `zAuthUserStored`. Anything that does not parse is dropped. */
	userSchema?: StandardSchemaV1
} = {}) {
	function readStored(): AuthUser[] {
		const parsed = jsonSafeParse(localStorage.getItem(storageKey) ?? "[]")
		if (!parsed.isOk || !Array.isArray(parsed.value)) return []
		const users: AuthUser[] = []
		const dropped: string[] = []
		for (const entry of parsed.value) {
			if (userSchema) {
				const result = userSchema["~standard"].validate(entry)
				if (result instanceof Promise) throw new Error("localOnlyUsers: async schemas cannot validate stored users.")
				if ("issues" in result) {
					dropped.push(String((entry as { username?: string }).username ?? (entry as { id?: string }).id))
					continue
				}
				users.push(deserializeAuthLocalUser(result.value as AuthUserStored))
			} else {
				users.push(deserializeAuthLocalUser(entry as AuthUserStored))
			}
		}
		if (dropped.length) {
			// eslint-disable-next-line no-console
			console.warn(`[nuxt-auth] localOnlyUsers dropped stored users that do not match userSchema: ${dropped.join(", ")}`)
		}
		return users
	}
	function writeStored(users: AuthUser[]): void {
		localStorage.setItem(storageKey, JSON.stringify(users))
	}

	function assertLoggedOut(method: string): void {
		if (useState(userStorageKey, () => undefined as any).value) {
			throw new Error(`${method}: a user is signed in, sign out before managing local users.`)
		}
	}

	return {
		id: "local-only-users" as const,
		getActions: () => ({
			localOnlyUsers: {
				list: (): AuthUser[] => {
					return readStored()
				},
				create: (username: string, { switch: doSwitch = true }: { switch?: boolean } = {}): AuthUser => {
					assertLoggedOut("localOnlyUsers.create")
					const now = new Date()
					const user: AuthUser = {
						id: crypto.randomUUID(),
						email: "",
						emailVerified: false,
						name: username,
						image: null,
						username,
						isRegistered: true,
						createdAt: now,
						updatedAt: now,
						type: "local"
					}
					const stored = readStored()
					if (stored.some(entry => entry.username === username)) {
						throw new Error(`localOnlyUsers.create: a user with the username "${username}" already exists.`)
					}

					writeStored([...stored, user])
					if (doSwitch) {
						useState(userStorageKey, () => undefined as any).value = user
						localStorage.setItem(userStorageKey, JSON.stringify(user))
					}
					return user
				},
				activate: (username: string): AuthUser | undefined => {
					assertLoggedOut("localOnlyUsers.activate")

					const user = readStored().find(entry => entry.username === username)
					if (!user) return undefined

					useState(userStorageKey, () => undefined as any).value = user
					localStorage.setItem(userStorageKey, JSON.stringify(user))
					return user
				},
				update: (id: string, patch: { username?: string, name?: string, image?: string }): AuthUser | undefined => {
					const stored = readStored()

					const user = stored.find(entry => entry.id === id)
					if (!user) return undefined

					const updated = { ...user, ...patch, updatedAt: new Date() }
					writeStored(stored.map(entry => entry.id === id ? updated : entry))

					const userData = useState(userStorageKey, () => undefined as any)
					if (userData.value?.id === id) {
						userData.value = updated
						localStorage.setItem(userStorageKey, JSON.stringify(updated))
					}
					return updated
				},
				delete: (id: string): void => {
					assertLoggedOut("localOnlyUsers.delete")
					writeStored(readStored().filter(entry => entry.id !== id))
					const userData = useState(userStorageKey, () => undefined as any)
					if (userData.value?.id === id) {
						userData.value = undefined
						localStorage.removeItem(userStorageKey)
					}
				},
				logout: (): void => {
					useState(userStorageKey, () => undefined as any).value = undefined
					localStorage.removeItem(userStorageKey)
				}
			}
		})
	}
}
