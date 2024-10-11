<template>
<div class="p-6 border-2 border-green-500 flex-1">
	Unauthenticated Only
</div>
</template>
<script lang="ts" setup>
definePageMeta({
	middleware: ["authProtected"],
	auth: {
		only: "unauthenticated"
	}
})
</script>
