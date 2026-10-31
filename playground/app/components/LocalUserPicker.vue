<template>
<WAuthLocalUsers
	:users="users"
	:provider-buttons-slot-props="providerButtonsSlotProps"
	@create="$emit('create', $event)"
	@login="$emit('login', $event)"
	@remove="$emit('delete', $event)"
/>
</template>

<script setup lang="ts">
import type { AuthLocalUser } from "@witchcraft/ui/types"

defineProps<{
	/** Slot props from `AuthLoginProviderButtons`, so the buttons match the provider buttons next to them. */
	providerButtonsSlotProps: { class: string, iconClass: string }
	users: AuthLocalUser[]
}>()

defineEmits<{
	create: [username: string]
	login: [user: AuthLocalUser]
	delete: [user: AuthLocalUser]
}>()
</script>
