<template>
<!-- Even though WRoot has data-allow-mismatch on the notifications component, it still causes issues because of https://github.com/vuejs/core/issues/12782 -->
<WRoot
	data-allow-mismatch="children"
	:is-client-side="isClientSide"
>
	<div class="p-2 flex gap-4 justify-between">
		<div class="flex gap-4">
			<NuxtLink to="/">Home</NuxtLink>
			<NuxtLink to="/authed">Authed Only</NuxtLink>
			<NuxtLink to="/unauthed">Unauthed Only</NuxtLink>
		</div>
		<div class="flex gap-4">
			<WButton @click="removeUser">
				Remove User
			</WButton>
			<AuthSessionStatus/>
		</div>
	</div>
	<div class="p-2 flex flex-col flex-1 justify-center items-center">
		<NuxtPage/>
	</div>
</WRoot>
</template>

<script lang="ts" setup>
const isClientSide = import.meta.client

async function removeUser() {
	await $fetch("/api/auth/users/remove", {
		method: "post"
	})
	await navigateTo("/", { external: true }) // force reload so cookies are cleared
}
</script>
