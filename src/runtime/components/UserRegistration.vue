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
	<div class="flex flex-col">
		<WLabel
			:for="usernameId"
		>
			Username
		</WLabel>
		<div>
			<WInputDeprecated
				:id="usernameId"
				name="username"
				class="w-0"
				inner-wrapper-class="bg-bg dark:bg-neutral-800"
				v-model="username"
			>
				<template #right>
					<WIcon class="w-[1rem] pointer-events-none">
						<slot
							v-if="isLoading"
							name="username-icon-loading"
						>
							<IconSpinner
								class="animate-spin text-neutral-500"
							/>
						</slot>
						<slot
							v-else-if="isValidUsername"
							name="username-icon-valid"
						>
							<IconCheck
								class="text-green-500"
							/>
						</slot>
						<slot
							v-else-if="anyError || (!isValidUsername && username !== '')"
							name="username-icon-invalid"
						>
							<IconInvalid
								class="text-red-500"
							/>
						</slot>
					</WIcon>
				</template>
			</WInputDeprecated>
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
		v-bind="{ error, registrationError }"
	>
		<div
			class="
		border
		border-red-500
		rounded-md
		p-2
		text-red-500
		bg-red-10j0
		dark:bg-red-900
		whitespace-pre-wrap
		break-all
	"
		>
			{{ registrationError || error }}
		</div>
	</slot>
</form>
</template>

<script lang="ts" setup>
import { refDebounced } from "@vueuse/core"

import { navigateTo, useAsyncData, useRuntimeConfig } from "#app"
import { computed, type Ref, ref, useId, useRoute } from "#imports"
import IconInvalid from "~icons/fa-solid/times"
import IconCheck from "~icons/fa6-solid/check"
import IconSpinner from "~icons/gg/spinner"

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
		}).catch(e => {
			if (e?.data?.code === AUTH_ERROR.USER_ALREADY_REGISTERED) {
				useAuth().setFetchUserOnNavigation(true)
				navigateTo(redirectUrl, { external: true })
			}
			error.value = `Registration Error: ${e.data.message}`
		})

		if (typeof res === "object" && res.redirectUrl) {
			navigateTo(res.redirectUrl, { external: true })
		}
	}
})
const usernameId = props.id ?? useId()
const username = ref("")
const debouncedUsername = refDebounced(username, props.debounce)
const registrationError = ref("")

const { data: isValidUsername, status, error } = await useAsyncData(
	"auth:username:valid",
	() => $fetch<boolean>(props.getValidUsernameRoute(debouncedUsername.value)),
	{
		watch: [debouncedUsername],
		immediate: false,
		default: () => false
	}
)

const isLoading = computed(() => username.value !== "" && (status.value === "pending" || username.value !== debouncedUsername.value))
const anyError = computed(() => error.value || registrationError.value)

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
