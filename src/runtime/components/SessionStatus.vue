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
					:class="`
					text-underline
					text-l
					${isSemiAuthed ? 'text-red-500' : ''}
				`"
					:title="isSemiAuthed ? 'You need to re-authenticate to use some parts of the app.' : ''"
					:to="usernameLink ? usernameLink(user) : defaultUsernameLink(user)"
				>
					{{ "username" in user ? user.username : user }}
				</NuxtLink>
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
import { useAuth } from "../composables/useAuth"
import type { AuthUser } from "../types.js"

const {
	logout,
	user,
	authRoutes,
	isAuthenticated,
	isSemiAuthed
} = useAuth()

// doing it this way, otherwise we can't reference local variables

function defaultUsernameLink(user: AuthUser) {
	return isSemiAuthed.value
		? useAuth().authRoutes.login
		: `/users/${"username" in user ? user.username : ""}`
}
/* const props =  */withDefaults(defineProps<{
	/** The link to the user's profile. Links to `/users/:username` (note this is not provided by the module). */

	usernameLink?: (user: AuthUser) => string
}>(), {
	usernameLink: undefined
})
</script>
