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
import { useAuthMocker } from "../composables/useAuthMocker.js"

const { provider, username, bypassRegistration, submit } = useAuthMocker()
</script>
