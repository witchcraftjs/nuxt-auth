<template>
<WRoot>
	<div class="p-2 flex gap-4 justify-between">
		<div class="flex gap-4">
			<NuxtLink to="/">Home</NuxtLink>
			<NuxtLink to="/authed">Authed Only</NuxtLink>
			<NuxtLink to="/unauthed">Unauthed Only</NuxtLink>
		</div>
		<AuthSessionStatus/>
	</div>
	<div class="p-2 flex flex-col">
		<NuxtPage/>
	</div>
</WRoot>
</template>

<script setup>

</script>
