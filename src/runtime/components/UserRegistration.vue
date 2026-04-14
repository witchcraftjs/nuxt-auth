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
					:aria-busy="isLoading"
					:aria-describedby="`${usernameId}-error`"
					name="username"
					class="w-0 pr-[calc(1rem+var(--spacing)*2)]"
					:valid="!anyError && (username === '' || isValidUsername)"
					:aria-invalid="!!anyError || (!isValidUsername && username !== '')"
					v-model="username"
				/>
				<div
					class="absolute top-0 bottom-0 pr-1 right-0"
					aria-live="polite"
				>
					<WIcon class="w-[1rem] pointer-events-none mt-px">
						<slot
							v-if="isLoading"
							name="username-icon-loading"
						>
							<IconSpinner
								class="animate-spin text-neutral-500"
							/>
							<span class="sr-only">Checking availability...</span>
						</slot>
						<slot
							v-else-if="isValidUsername"
							name="username-icon-valid"
						>
							<IconCheck
								class="text-green-500 scale-110"
							/>
							<span class="sr-only">Username available.</span>
						</slot>
						<slot
							v-else-if="anyError || (!isValidUsername && username !== '')"
							name="username-icon-invalid"
						>
							<IconInvalid
								class="text-red-500"
							/>
							<span class="sr-only">Username unavailable.</span>
						</slot>
					</WIcon>
				</div>
			</div>
		</div>
	</div>
	<slot/>
	<WButton
		:id="submitId"
		:disabled="!!error || isLoading || username === '' || !isValidUsername"
		class="w-full"
		type="submit"
	>
		Register
	</WButton>
	<slot
		v-if="anyError"
		name="error"
		v-bind="{ error, registrationError, localUsernameError, id: `${usernameId}-error` }"
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
			{{ localUsernameError || registrationError || error }}
		</div>
	</slot>
</form>
</template>

<script lang="ts" setup>
import { refDebounced } from "@vueuse/core"
import z from "zod"

import { navigateTo, useAsyncData, useRuntimeConfig } from "#app"
import { computed, type Ref, ref, useId, useRoute } from "#imports"
import IconCheck from "~icons/lucide/check"
import IconSpinner from "~icons/lucide/loader-circle"
import IconInvalid from "~icons/lucide/x"

import { useAuth } from "../composables/useAuth.js"
import { AUTH_ERROR, defaultZodUsernameSchema } from "../types.js"
import { getAuthApiRoute } from "../utils/getAuthApiRoute.js"

const query = useRoute().query
const submitId = useId()
const props = withDefaults(defineProps<{
	debounce?: number
	/** Can throw to indicate the username is invalid (before a request to properly check it is even made. The default throws if the default username schema isn't met. */
	getValidUsernameRoute?: (username: string) => string
	onSubmitRegistration?: (
		event: Event,
		username: string,
		error: Ref<string>,
		redirectUrl: string,
		deeplink?: string
	) => void
	id?: string
	/**
	 * When a validator is provided, if it errors, the server is not queried so as to avoid invalid queries. Any errors it produces are also shown.
	 *
	 * @default defaultZodUsernameSchema
	 */
	usernameSchema?: z.ZodType<string, any, any>
}>(), {
	debounce: 1000,
	getValidUsernameRoute: (username: string) => {
		const res = defaultZodUsernameSchema.safeParse(username)
		if (!res.success) throw new Error(res.error.format()._errors.join("\n"))
		return getAuthApiRoute(useRuntimeConfig().public, "usernameValid", { username })
	},
	onSubmitRegistration: async (
		_event: Event,
		username: string,
		error: Ref<string>,
		redirectUrl: string,
		deeplink?: string
	) => {
		const res = await $fetch<true | { redirectUrl: string }>(`${getAuthApiRoute(useRuntimeConfig().public, "register")}${deeplink ? `?deeplink=${deeplink}` : ""}`, {
			cache: "no-store",
			method: "post",
			body: {
				username
			}
		}).catch(async e => {
			error.value = `Registration Error: ${e.data.message}`

			if (e?.data?.code === AUTH_ERROR.USER_ALREADY_REGISTERED) {
				useAuth().setFetchUserOnNavigation(true)
				await navigateTo(redirectUrl, { external: true })
			}
		})

		if (typeof res === "object" && res.redirectUrl) {
			await navigateTo(res.redirectUrl, { external: true })
		}
	},
	usernameSchema: defaultZodUsernameSchema as any
})
const usernameId = props.id ?? useId()
const username = ref("")
const debouncedUsername = refDebounced(username, props.debounce)
const registrationError = ref("")

const localUsernameError = computed(() => {
	const res = props.usernameSchema.safeParse(username.value)
	if (res.success) return undefined
	return z.prettifyError(res.error).replaceAll("✖", "❌")
})
const { data: isValidUsername, status, error } = await useAsyncData(
	"auth:username:valid",
	async () => {
		if (localUsernameError.value) return false
		return $fetch<boolean>(props.getValidUsernameRoute(debouncedUsername.value))
	},
	{
		watch: [localUsernameError, debouncedUsername],
		immediate: false,
		default: () => false
	}
)

const isLoading = computed(() => {
	if (localUsernameError.value) return false
	return username.value !== "" && (status.value === "pending" || username.value !== debouncedUsername.value)
})

const anyError = computed(() => localUsernameError.value || error.value || registrationError.value)

const deeplink = typeof query.deeplink === "string" ? query.deeplink : undefined
const redirect = deeplink
	? useRuntimeConfig().public.auth.authRoutes.externalCode
	: useRuntimeConfig().public.auth.authRoutes.register

if (!redirect) throw new Error("No externalCode or register route defined.")

function handleSubmit(event: Event) {
	props.onSubmitRegistration(
		event,
		username.value,
		registrationError,
		redirect!,
		deeplink
	)
}
</script>
