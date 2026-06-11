<template>
<div class="flex flex-col justify-center gap-4">
	<div class="text-lg text-center">
		{{ promptText }}
	</div>

	<NuxtLink
		class="
				px-1
				text-center
				hover:shadow-xs
				text-xl
				border-2
				border-accent-500
				rounded-sm
				hover:border-accent-400

	"
		:to="deepLinkUrl"
		:external="true"
	>
		{{ openAppText }}
	</NuxtLink>
	<WButton
		:title="copyTitle"
		class="
				text-xl
				bg-accent-100
				dark:bg-accent-950/50
				rounded-sm
				border-2
				border-dashed
				p-4
				border-accent-500
				dark:border-accent-600
				select-text
				after:shadow-none
				hover:border-accent-400
				hover:text-accent-500
				break-all
			"
		@click="copyToken"
	>
		{{ accessToken }}
	</WButton>
</div>
</template>

<script lang="ts" setup>
import { useAuthExternalCode } from "../composables/useAuthExternalCode.js"

const { accessToken, deepLinkUrl, copyToken } = useAuthExternalCode()

withDefaults(defineProps<{
	openAppText?: string
	promptText?: string
	copyTitle?: string
}>(), {
	openAppText: "Open App and Authorize",
	promptText: "If you are not prompted to open the app, try clicking below or copy this token into the app:",
	copyTitle: "Click to Copy"
})
</script>
