<template>
<div class="min-h-screen flex flex-col items-center justify-center h-full flex-1">
	<AuthUserRegistration/>
</div>
</template>

<script lang="ts" setup>

definePageMeta({
	middleware: ["authProtected"],
	auth: {
		only: "authenticated-unregistered",
	}
})
</script>
