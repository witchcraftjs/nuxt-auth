<template>
<div class="flex flex-col gap-1">
	<span>Bypass auth using {{ provider }} provider as user: </span>
	<WSimpleInput
		class="bg-bg dark:bg-neutral-800"
		label="Username"
		v-model="username"
	/>
	<WCheckbox
		class="bg-bg dark:bg-neutral-800 dark:checked:after:border-neutral-800"
		label="Bypass Registration for New Users"
		v-model="bypassRegistration"
	/>
	<WButton @click="submit">
		Submit
	</WButton>
</div>
</template>

<script setup lang="ts">
import { navigateTo, useRoute } from "#app"
import { ref, useRuntimeConfig } from "#imports"

import { getAuthApiRoute } from "../utils/getAuthApiRoute.js"

const username = ref("")
const bypassRegistration = ref(false)
const provider = useRoute().query.provider
if (!provider || typeof provider !== "string") throw new Error("Missing provider query param.")
async function submit() {
	const query = useRoute().query
	delete query.provider
	const route = getAuthApiRoute(useRuntimeConfig().public, "callback", { provider: provider as string }, {
		devBypass: true,
		username: username.value,
		devBypassRegistration: bypassRegistration.value,
		...query
	})
	await navigateTo(route, { external: true })
}
</script>
