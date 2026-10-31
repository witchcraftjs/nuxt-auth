<template>
<div class="flex flex-col gap-1">
	<span>Bypass auth using {{ provider }} provider as user: </span>
	<AuthMockBypassRegistrationFields
		v-model:username="username"
		v-model:bypass-registration="bypassRegistration"
	/>
	<WButton @click="submit">
		Submit
	</WButton>
</div>
</template>

<script setup lang="ts">
import { useAuthMocker } from "../composables/useAuthMocker.js"

const props = defineProps<{
	/** Scheme of the deeplink the mock redirects to, from `rc.auth.deeplinkSchemes`. Defaults to the electron scheme. */
	deeplinkScheme?: string
}>()

const { provider, username, bypassRegistration, submit } = useAuthMocker({ deeplinkScheme: props.deeplinkScheme })
</script>
