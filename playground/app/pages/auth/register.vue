<!-- This is a server only page, do not include in external app. -->
<template>
<div class="min-h-screen flex flex-col items-center justify-center h-full flex-1">
	<AuthUserRegistration :auth="useConfiguredAuth()"/>
</div>
</template>

<script lang="ts" setup>
definePageMeta({
	middleware: ["authProtected"],
	auth: {
		only: "authenticated-unregistered",
		// electron users need to register in the browser
		// they cannot be redirected to `/register` it won't and shouldn't exist
		redirectTo: () => isElectron() ? "$login" : undefined
	}
})
</script>
