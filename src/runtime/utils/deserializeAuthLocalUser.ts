import type { AuthUser, AuthUserStored } from "../types.js"

export function deserializeAuthLocalUser(user: AuthUserStored): AuthUser {
	const base = {
		...user,
		image: user.image ?? null,
		createdAt: new Date(user.createdAt),
		updatedAt: new Date(user.updatedAt)
	}
	return user.type === "local"
		? { ...base, type: "local", username: user.username }
		: { ...base, type: user.type, username: user.username ?? null }
}
