<template>
<WAuth
	:class="($attrs as any)?.class"
	:providers="enabledProviders"
	:provider-styles="fullProviderStyles"
	@login="emit('login', $event)"
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
import { pick } from "@alanscodelog/utils/pick"
import WAuth from "@witchcraft/ui/components/WAuth"
import defu from "defu"

import { useRuntimeConfig } from "#app"
import { computed, useAttrs } from "#imports"

import { providerStyles as baseProviderStyles } from "../core/providerStyles.js"
import type { ProviderStyle } from "../types.js"

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

const emit = defineEmits<{
	login: [provider: string]
}>()

const props = withDefaults(defineProps<{
	providerStyles?: Record<string, Partial<ProviderStyle>>
}>(), {
	providerStyles: () => ({} as any)
})

const fullProviderStyles = computed(() =>
	defu(
		props.providerStyles,
		pick(baseProviderStyles, enabledProviders)
	) as Record<string, Partial<ProviderStyle>>)
</script>
