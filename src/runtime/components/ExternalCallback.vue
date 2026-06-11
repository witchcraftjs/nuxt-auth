<template>
<div class="flex flex-col gap-4">
	<template v-if="authUri">
		<div class="text-xl text-center">
			Authorize
		</div>
		<div class="text-lg text-center">
			If you are not redirected automatically, open following URL and paste the code given:
			<NuxtLink
				class="link-like underline"
				:href="authUri"
				target="_blank"
			>
				{{ authUri }}
			</NuxtLink>
		</div>
		<form
			class="flex flex-col gap-4"
			@submit.prevent="authorize(manualAccessToken)"
		>
			<WInputDeprecated
				placeholder="Paste Code Here"
				v-model="manualAccessToken"
				@update:model-value="error=undefined"
			/>
			<div
				v-if="error"
				class="border-2 border-red-500 bg-red-100 dark:bg-red-900 rounded-md p-2"
			>
				{{ error }}
			</div>
			<WButton
				:disabled="!manualAccessToken || manualAccessToken.length === 0"
				type="submit"
			>
				Submit
			</WButton>
			<WButton
				type="button"
				@click="cancel"
			>
				Cancel
			</WButton>
		</form>
	</template>
	<template v-else>
		<div class="text-xl text-center">
			Authorizing...
		</div>
		<WButton @click="authorize(initialAccessToken)">
			Retry
		</WButton>
	</template>
</div>
</template>

<script lang="ts" setup>
import type { ExternalCallbackOptions } from "../composables/useAuthExternalCallback.js"
import { useAuthExternalCallback } from "../composables/useAuthExternalCallback.js"

const props = defineProps<ExternalCallbackOptions>()

const { authUri, initialAccessToken, manualAccessToken, error, authorize, cancel } = useAuthExternalCallback(props)
</script>
