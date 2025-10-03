<template>
<div
	class="
	flex
	flex-wrap
	items-center
	justify-center
	items-center
	h-screen
	p-6
	gap-6
"
>
	<div class="flex justify-center items-center basis-1/2">
		<div class="p-6 border-8 border-double border-neutral-500 flex flex-col items-center justify-center gap-2">
			<div class="font-serif text-7xl text-center">
				{{ appName }}
			</div>
			<div
				v-if="appSubName"
				class="
				text-2xl
				text-neutral-600
				dark:text-neutral-400
				text-center
			"
			>
				{{ appSubName }}
			</div>
		</div>
	</div>
	<div class="flex-1 whitespace-nowrap">
		<AuthLoginProviderButtons :use-auth-options="{ handleActions }"/>
	</div>
</div>
</template>

<script setup lang="ts">
import type { ActionHandler } from "#auth/types.js"
import { useRuntimeConfig } from "#imports"

const appInfo = useRuntimeConfig().public.appInfo
const appName = appInfo.name
const appSubName = appInfo.subName

definePageMeta({
	middleware: ["authProtected"],
	auth: {
		only: "unauthenticated"
	}
})

const handleActions: ActionHandler = (_action, _url) => {
	// if (doCustomAction) {
	// 	...
	// 	return true
	// }
	return false
}
</script>
