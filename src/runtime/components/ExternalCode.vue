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
		@click="copy(accessToken as string)"
	>
		{{ accessToken }}
	</WButton>
</div>
</template>

<script lang="ts" setup>
import { unreachable } from "@alanscodelog/utils/unreachable"
import { copy } from "@witchcraft/ui/helpers/copy"

import {
	navigateTo,
	onMounted,
	useRoute
} from "#imports"

import { decodeQueryUri } from "../utils/decodeQueryUri.js"

const query = useRoute().query
const accessToken = query.accessToken
if (typeof accessToken !== "string") {
	unreachable("No session_token.")
}
const deepLinkUrl = decodeQueryUri(query.deeplinkUri)
if (!deepLinkUrl) {
	unreachable("No deeplinkUrl could be decoded.")
}
/* const props =  */withDefaults(defineProps<{
	openAppText?: string
	promptText?: string
	copyTitle?: string
}>(), {
	openAppText: "Open App and Authorize",
	promptText: "If you are not prompted to open the app, try clicking below or copy this token into the app:",
	copyTitle: "Click to Copy"
})
onMounted(() => {
	if (accessToken) {
		void navigateTo(deepLinkUrl, { external: true })
	}
})
</script>
