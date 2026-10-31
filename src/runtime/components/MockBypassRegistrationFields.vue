<template>
<WSimpleInput
	class="bg-bg dark:bg-neutral-800"
	aria-label="Username"
	placeholder="Username"
	v-model="username"
/>
<WCheckbox
	class="bg-bg dark:bg-neutral-800 dark:checked:after:border-neutral-800"
	label="Bypass Registration for New Users"
	v-model="bypassRegistration"
/>
</template>

<script setup lang="ts">
const username = defineModel<string>("username", { required: true })
const bypassRegistration = defineModel<boolean>("bypassRegistration", { required: true })
</script>
