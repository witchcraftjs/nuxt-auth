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
		<div>
			<div class="input-wrapper relative flex">
				<WSimpleInput
					:id="usernameId"
					:aria-busy="status === 'loading'"
					:aria-describedby="`${usernameId}-error`"
					name="username"
					class="w-0 pr-[calc(1rem+var(--spacing)*2)]"
					:valid="inputValid"
					:aria-invalid="!inputValid"
					v-model="username"
				/>
				<div
					class="absolute top-0 bottom-0 pr-1 right-0"
					aria-live="polite"
				>
					<WIcon class="w-[1rem] pointer-events-none mt-px">
						<slot
							v-if="status === 'loading'"
							name="username-icon-loading"
						>
							<IconSpinner class="animate-spin text-neutral-500"/>
							<span class="sr-only">{{ statusText }}</span>
						</slot>
						<slot
							v-else-if="status === 'valid'"
							name="username-icon-valid"
						>
							<IconCheck class="text-green-500 scale-110"/>
							<span class="sr-only">{{ statusText }}</span>
						</slot>
						<slot
							v-else-if="status === 'invalid'"
							name="username-icon-invalid"
						>
							<IconInvalid class="text-red-500"/>
							<span class="sr-only">{{ statusText }}</span>
						</slot>
					</WIcon>
				</div>
			</div>
		</div>
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
	<slot
		v-if="errors.length"
		name="error"
		v-bind="{ errors, id: `${usernameId}-error` }"
	>
		<div
			:id="`${usernameId}-error`"
			class="
				border
				border-red-500
				rounded-md
				p-2
				text-red-500
				bg-red-100
				dark:bg-red-950/50
				whitespace-pre-wrap
				break-all
			"
		>
			<div
				v-for="err in errors"
				:key="err"
			>
				{{ err }}
			</div>
		</div>
	</slot>
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

import { useId } from "#imports"
import IconCheck from "~icons/lucide/check"
import IconSpinner from "~icons/lucide/loader-circle"
import IconInvalid from "~icons/lucide/x"

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
	inputValid
} = useAuthUserRegistration({
	debounce: props.debounce,
	usernameSchema: props.usernameSchema
})
</script>
