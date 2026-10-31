<template>
<div class="p-6 border-2 border-red-500 flex-1 w-full flex flex-col items-center gap-4">
	<div>Authenticated Registered Only</div>
	<table class="border-2 border-neutral-500">
		<tbody class="divide-y divide-neutral-500">
			<tr>
				<td class="p-2">
					Session (middleware)
				</td>
				<td class="p-2">
					{{ isExpiredState ? "expired" : "active" }}
				</td>
			</tr>
			<tr>
				<td class="p-2">
					<WButton @click="checkExpiry">
						Check expiry
					</WButton>
				</td>
				<td class="p-2">
					{{ localExpiry }}
				</td>
			</tr>
			<tr>
				<td class="p-2">
					<WButton @click="checkServer">
						Check server
					</WButton>
				</td>
				<td class="p-2">
					{{ serverSession }}
				</td>
			</tr>
			<tr>
				<td class="p-2">
					<WButton @click="requestReauth">
						Request re-auth
					</WButton>
				</td>
				<td class="p-2">
					{{ reauth }}
				</td>
			</tr>
		</tbody>
	</table>
	<WSimpleInput
		label="Name"
		v-model="name"
	/>
	<WButton @click="updateName">
		Update name
	</WButton>
	<WSimpleInput
		label="Current password"
		type="password"
		v-model="currentPassword"
	/>
	<WSimpleInput
		label="New password"
		type="password"
		v-model="newPassword"
	/>
	<WButton @click="changePassword">
		Change password
	</WButton>
	<div
		v-if="error"
		class="border-2 border-red-500 p-2 flex flex-col items-center"
	>
		<div class="font-bold">
			{{ error.name }}
		</div>
		<div>{{ error.message }}</div>
	</div>
</div>
</template>

<script lang="ts" setup>
import { isExpiredStateKey } from "#witchcraft-nuxt-auth/types"

definePageMeta({
	middleware: "authProtected",
	auth: {
		only: "authenticated-registered",
		redirectTo: "$login",
		// to enable local users
		disableServerRedirect: true
	}
})

const { authRoutes, client, isExpired, update, user } = useConfiguredAuth()

const name = ref("")
const currentPassword = ref("")
const newPassword = ref("")
const error = ref<Error>()
const isExpiredState = useState(isExpiredStateKey, () => false)
const localExpiry = ref("not checked")
const serverSession = ref("not checked")
const reauth = ref("not requested")

function setError(cause: unknown): void {
	error.value = cause instanceof Error ? cause : new Error(String(cause))
}

function checkExpiry(): void {
	try {
		localExpiry.value = isExpired() ? "expired" : "active"
	} catch (cause) {
		localExpiry.value = cause instanceof Error ? cause.message : String(cause)
	}
}

async function checkServer(): Promise<void> {
	serverSession.value = "checking"
	await client.getSession()
		.then(({ data }) => {
			serverSession.value = data?.user ? "signed in" : "no session"
		})
		.catch((cause: unknown) => {
			serverSession.value = cause instanceof Error ? cause.message : String(cause)
		})
}

async function requestReauth(): Promise<void> {
	reauth.value = "sent to the login page"
	await navigateTo(authRoutes.login)
}

async function updateName(): Promise<void> {
	error.value = undefined
	await update({ name: name.value }).catch(setError)
}

async function changePassword(): Promise<void> {
	error.value = undefined
	// methods outside of the ones useAuth wrap do not have auto-gating based on user type, you must do the gating yourself if you want to use them
	if (user.value?.type === "local") return setError(new Error("not available for a local-only user"))
	await client.changePassword({ currentPassword: currentPassword.value, newPassword: newPassword.value }).catch(setError)
}
</script>
