<template>
<form
	class="
		flex-1
		flex
		flex-col
		justify-center
		gap-4
		w-[500px]
		max-w-full
		p-10
	"
	@submit.prevent="handleSubmit"
>
	<div class="flex flex-col items-stretch">
		<label
			:for="usernameId"
			class="text-sm"
		>
			Username
		</label>
		<WAsyncValidatedInput
			:id="usernameId"
			:errors="isDebouncing||username ===''?[]:errors"
			:status="status"
			:status-text="statusText"
			:can-submit="canSubmit"
			:input-valid="isDebouncing || inputValid"
			v-model="username"
		/>
	</div>
	<slot/>
	<WButton
		:id="submitId"
		:disabled="!canSubmit"
		class="w-full"
		type="submit"
	>
		Register
	</WButton>
</form>
</template>

<script lang="ts">
/**
 * @deprecated This component is deprecated and will be removed in a future version.
 */
export default {}
</script>

<script lang="ts" setup>
import type { StandardSchemaV1 } from "@standard-schema/spec"
import { WAsyncValidatedInput } from "@witchcraft/ui/components"

import { useId } from "#imports"

import { useAuthUserRegistration } from "../composables/useAuthUserRegistration.js"

if (import.meta.dev) {
	// eslint-disable-next-line no-console
	console.warn("[nuxt-auth] <UserRegistration> is deprecated and will be removed in a future version.")
}

const props = defineProps<{
	debounce?: number
	usernameSchema?: StandardSchemaV1<string, string>
	id?: string
}>()

const usernameId = props.id ?? useId()
const submitId = useId()

const {
	username,
	errors,
	status,
	statusText,
	canSubmit,
	handleSubmit,
	inputValid,
	isDebouncing
} = useAuthUserRegistration({
	debounce: props.debounce,
	usernameSchema: props.usernameSchema,
	statusTextMap: {
		loading: "Checking availability...",
		valid: "Username available.",
		invalid: "Username unavailable."
	}
})
</script>
