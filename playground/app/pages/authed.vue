<template>
<div class="p-6 border-2 border-red-500 flex-1">
	Authenticated Registered Only
</div>
</template>

<script lang="ts" setup>
definePageMeta({
	middleware: "authProtected",
	auth: {
		only: "authenticated-registered",
		redirectTo: "$login"
	}
})
</script>
