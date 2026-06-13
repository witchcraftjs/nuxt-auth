<template>
<WAuth
	:class="($attrs as any)?.class"
	:providers="enabledProviders"
	:provider-styles="providerStyles"
	@login="onLogin"
>
	<template #extra="slotProps">
		<slot
			name="extra"
			v-bind="slotProps"
		/>
	</template>
</WAuth>
</template>

<script lang="ts">
/**
 * @deprecated This component is deprecated and will be removed in a future version.
 */
export default {}
</script>

<script setup lang="ts">
import WAuth from "@witchcraft/ui/components/WAuth"

import { useRuntimeConfig } from "#app"
import { useAttrs } from "#imports"

import { useAuth } from "../composables/useAuth.js"
import type { ProviderNames, ProviderStyle, UseAuthComposableOptions } from "../types.js"

if (import.meta.dev) {
	// eslint-disable-next-line no-console
	console.warn("[nuxt-auth] <LoginProviderButtons> is deprecated and will be removed in a future version.")
}

defineOptions({
	inheritAttrs: false
})

const rc = useRuntimeConfig()
const config = rc.public.auth
const enabledProviders = config.enabledProviders
const $attrs = useAttrs()

const props = withDefaults(defineProps<{
	providerStyles?: Record<ProviderNames, Partial<ProviderStyle>>
	useAuthOptions?: UseAuthComposableOptions
	loginOptions?: Parameters<ReturnType<typeof useAuth>["login"]>[1]
}>(), {
	providerStyles: () => ({} as any),
	useAuthOptions: () => ({}),
	loginOptions: () => ({})
})

const { login } = useAuth(props.useAuthOptions)

function onLogin(provider: string) {
	login(provider as any, props.loginOptions)
}
</script>
