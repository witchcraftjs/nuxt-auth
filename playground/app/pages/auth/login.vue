<template>
<div
	class="
	flex
	flex-wrap
	justify-center
	items-center
	gap-6
	p-6
	max-w-[1000px]
"
>
	<div class="flex justify-center items-center basis-1/2 max-h-min ">
		<div
			class="p-6 border-8 border-double border-neutral-500 flex flex-col items-center justify-center gap-2"
		>
			<div
				class="font-serif text-4xl sm:text-6xl md:text-7xl text-center"
			>
				{{ appName }}
			</div>
			<div
				v-if="appSubName"
				class="text-xl md:text-2xl text-neutral-600 dark:text-neutral-400 text-center"
			>
				{{ appSubName }}
			</div>
		</div>
	</div>
	<div
		class="
			flex-1
			whitespace-nowrap
			justify-center
			items-stretch
			flex
			flex-col
			gap-4
		"
	>
		<AuthLoginProviderButtons
			:provider-styles="providerStyles"
			@login="provider => login(provider, {
				devBypass,
				username: mockUsername,
				devBypassRegistration: mockBypassRegistration
			})"
		>
			<template #extra="slotProps">
				<WButton
					:class="slotProps.class"
				>
					<WIcon :class="slotProps.iconClass">
						<i-mdi-local/>
					</WIcon>
					<div class="">
						Example Extra Slot Button
					</div>
				</WButton>
				<WButton
					:class="slotProps.class"
				>
					<WIcon :class="slotProps.iconClass">
						<i-mdi-local/>
					</WIcon>
					<div class="">
						Small Button
					</div>
				</WButton>
				<LocalUserPicker
					:users="localUsers"
					:provider-buttons-slot-props="{ class: slotProps.class, iconClass: slotProps.iconClass }"
					@create="login('local', { username: $event })"
					@login="login('local', { username: $event.username })"
					@delete="remove($event.id)"
				/>
			</template>
		</AuthLoginProviderButtons>
		<WCheckbox
			v-if="devBypassAuth"
			label="Dev Bypass/Mock Auth"
			v-model="devBypass"
		/>
		<AuthMockBypassRegistrationFields
			v-if="showMockFields"
			v-model:username="mockUsername"
			v-model:bypass-registration="mockBypassRegistration"
		/>
	</div>
</div>
</template>

<script setup lang="ts">
import type { AuthLocalUser } from "@witchcraft/ui/types"

import { useRuntimeConfig } from "#imports"
import { providerStyles } from "#witchcraft-nuxt-auth/core/providerStyles"

const appInfo = useRuntimeConfig().public.appInfo
const appName = appInfo.name
const appSubName = appInfo.subName
const devBypassAuth = useRuntimeConfig().public.auth.devBypassAuth
const devBypass = ref(false)
const mockUsername = ref("")
const mockBypassRegistration = ref(false)
const showMockFields = isElectron() && window.__IS_TEST === true


definePageMeta({
	middleware: ["authProtected"],
	auth: {
	// a user whose session expired is kept, so it counts as authenticated, but it belongs here to sign in again
		only: (auth: ReturnType<typeof useAuth>) => !auth.isAuthenticated.value
			|| (import.meta.client && auth.user.value?.type === "external" && auth.isExpired())
	}
})

const localUsers = ref<AuthLocalUser[]>([])

const { login, list, delete: remove } = useConfiguredAuth()


async function refreshLocalUsers(): Promise<void> {
	const users: AuthLocalUser[] = []
	for (const user of await list()) {
		if (user.type !== "local") continue
		users.push({ id: user.id, username: user.username, isLocal: true })
	}
	localUsers.value = users
}

onMounted(refreshLocalUsers)
</script>
