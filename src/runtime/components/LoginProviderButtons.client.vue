<template>
<div
	:class="twMerge(`
		flex-1
		flex
		flex-col
		items-stretch
		justify-center
		gap-2
	`, ($attrs as any)?.class)"
>
	<template
		v-for="provider in enabledProviders"
		:key="provider"
	>
		<!-- custom id is because useId is causing hydration mismtaches :/
		I think because of the for loop -->
		<WButton
			v-if="provider"
			:id="'login-provider-' + provider"
			type="button"
			:class="twMerge(`text-l p-2 px-4 [&_label]:justify-start [&_label]:gap-4`, providerStyles[provider]?.class)"
			:key="provider"
			@click="login(provider, loginOptions)"
		>
			<WIcon
				v-if="providerStyles[provider]?.logo"
				class="text-xl"
			>
				<component
					:is="providerStyles[provider]?.logo"
				/>
			</WIcon>
			<div>
				Sign in / Register with {{ providerStyles[provider]?.name ?? provider }}
			</div>
		</WButton>
	</template>
	<slot
		name="extra"
		icon-class="text-xl"
		class="text-l p-2 px-4 [&_label]:justify-start [&_label]:gap-4"
	/>
</div>
</template>

<script lang="ts">
/**
 * @deprecated This component is deprecated and will be removed in a future version.
 */
export default {}
</script>

<script setup lang="ts">
import { twMerge } from "@witchcraft/ui/utils/twMerge"

import { useRuntimeConfig } from "#app"
import { useAttrs } from "#imports"

import { useAuth } from "../composables/useAuth.js"
import type { ProviderNames, ProviderStyle, UseAuthComposableOptions } from "../types.js"

if (import.meta.dev) {
	// eslint-disable-next-line no-console
	console.warn("[nuxt-auth] <LoginProviderButtons> is deprecated and will be removed in a future version.")
}

const rc = useRuntimeConfig()
const config = rc.public.auth
const enabledProviders = config.enabledProviders
const $attrs = useAttrs()

const props = withDefaults(defineProps<{
	providerStyles?: Record<ProviderNames, Partial<ProviderStyle>>
	useAuthOptions?: UseAuthComposableOptions
	loginOptions?: Parameters<ReturnType<typeof useAuth>["login"]>[1]
}>(), {
	providerStyles: () => ({}) as any,
	useAuthOptions: () => ({}),
	loginOptions: () => ({})
})
const { login } = useAuth(props.useAuthOptions)
</script>
