<template>
<div v-if="isAuthenticated && user">
	<slot
		v-if="isAuthenticated"
		name="authenticated-registered"
		:user="user"
		:auth-routes="authRoutes"
	>
		<div class="flex gap-4">
			<slot
				name="user"
				:user="user"
			>
				<NuxtLink
					v-if="profileLink"
					:class="`
					text-underline
					text-l
					${isExternalExpiredUser ? 'text-red-500' : ''}
				`"
					:title="isExternalExpiredUser ? 'You need to re-authenticate to use some parts of the app.' : ''"
					:to="profileLink"
					@click="openInBrowser($event)"
				>
					{{ "username" in user ? user.username : user }}
				</NuxtLink>
				<span v-else>
					{{ "username" in user ? user.username : user }}
				</span>
			</slot>
			<WButton
				:unstyle="true"
				class=""
				@click="logout()"
			>
				Logout
			</WButton>
		</div>
	</slot>
	<slot
		v-else
		name="authenticated-unregistered"
		:user="user"
		:auth-routes="authRoutes"
	>
		<div class="flex gap-4">
			<NuxtLink
				:to="authRoutes.register"
			>
				Register
			</NuxtLink>
			<WButton
				:unstyle="true"
				@click="logout()"
			>
				Logout
			</WButton>
		</div>
	</slot>
</div>
<div v-else>
	<slot
		name="unauthenticated"
		:auth-routes="authRoutes"
	>
		<NuxtLink
			:to="authRoutes.login"
		>
			Login / Register
		</NuxtLink>
	</slot>
</div>
</template>

<script lang="ts" setup>
import { computed, useRuntimeConfig, useState } from "#imports"

import { useAuth } from "../composables/useAuth"
import type { AuthUser } from "../types.js"
import { isExpiredStateKey } from "../types.js"

const {
	logout,
	user,
	authRoutes,
	isAuthenticated,
	isExternal
} = useAuth()


const props = withDefaults(defineProps<{
	/** The link to the user's profile. Links to `/users/:username` (note this is not provided by the module). */
	usernameLink?: (user: AuthUser) => string
}>(), {
	usernameLink: undefined
})

const publicServerUrl = (useRuntimeConfig().public.auth as any).publicServerUrl as string | undefined

const isExpired = useState(isExpiredStateKey, () => false)

const isExternalExpiredUser = computed(() => user.value?.type === "external" && isExpired.value)

const profileLink = computed(() => {
	if (!user.value) return undefined
	const username = "username" in user.value ? user.value.username ?? "" : ""
	// a local user only exists in this app, there is no page of theirs on the server
	const appPath = `/users/${username}`
	if (user.value.type === "local") return appPath
	return props.usernameLink
		? props.usernameLink(user.value)
		: publicServerUrl && user.value.type !== undefined
			? `${publicServerUrl}/users/${username}`
			: appPath
})

// A server page is not one an electron window can show, so that one goes to the system browser. A
// local user's page is in the app, so theirs is a normal link.
function openInBrowser(event: MouseEvent): void {
	if (!isExternal.value || user.value?.type === "local") return
	const open = (globalThis as any).electron?.api?.open
	if (typeof open !== "function" || !profileLink.value) return
	event.preventDefault()
	open(profileLink.value)
}
</script>
