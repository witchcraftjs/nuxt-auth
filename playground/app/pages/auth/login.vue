<template>
<div
	class="
	flex
	flex-wrap
	justify-center
	items-center
	gap-6
	p-6
	max-w-[1000px]
"
>
	<div class="flex justify-center items-center basis-1/2 max-h-min ">
		<div
			class="p-6 border-8 border-double border-neutral-500 flex flex-col items-center justify-center gap-2"
		>
			<div
				class="font-serif text-4xl sm:text-6xl md:text-7xl text-center"
			>
				{{ appName }}
			</div>
			<div
				v-if="appSubName"
				class="text-xl md:text-2xl text-neutral-600 dark:text-neutral-400 text-center"
			>
				{{ appSubName }}
			</div>
		</div>
	</div>
	<div
		class="
			flex-1
			whitespace-nowrap
			justify-center
			flex
			[&>div]:max-w-max
		"
	>
		<AuthLoginProviderButtons :use-auth-options="{ handleActions }">
			<template #extra="slotProps">
				<WButton
					:class="slotProps.class"
				>
					<WIcon :class="slotProps.iconClass">
						<i-mdi-local/>
					</WIcon>
					<div class="">
						Example Extra Slot Button
					</div>
				</WButton>
				<WButton
					:class="slotProps.class"
				>
					<WIcon :class="slotProps.iconClass">
						<i-mdi-local/>
					</WIcon>
					<div class="">
						Small Button
					</div>
				</WButton>
			</template>
		</AuthLoginProviderButtons>
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
