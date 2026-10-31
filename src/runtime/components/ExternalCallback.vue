<template>
<div class="flex flex-col gap-4">
	<template v-if="!initialAccessToken">
		<div class="text-xl text-center">
			Authorize
		</div>
		<div class="text-lg text-center">
			If you were not redirected automatically, click open and paste the code given:
		</div>
		<WButton
			type="button"
			@click="requestExternalAuth"
		>
			Open Browser
		</WButton>
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

const { initialAccessToken, manualAccessToken, error, authorize, requestExternalAuth, cancel } = useAuthExternalCallback(props)
</script>
