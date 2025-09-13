<template>
<div
	class="
	flex-1
	flex
	flex-col
	items-center
	justify-center
	gap-2
"
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
			class="p-2 text-l"
			:style="styles[provider]"
			:key="provider"
			@click="login(provider, loginOptions)"
		>
			<WIcon
				v-if="styles[provider]?.logo"
				class="px-2 text-xl"
			>
				<component
					:is="styles[provider]?.logo"
				/>
			</WIcon>
			Sign in / Register with {{ styles[provider]?.name ?? provider }}
		</WButton>
	</template>
</div>
</template>

<script setup lang="ts">
import { useInjectedDarkMode } from "@witchcraft/ui/composables/useInjectedDarkMode"
import defu from "defu"

import { useRuntimeConfig } from "#app"
import { computed } from "#imports"

import { useAuth } from "../composables/useAuth.js"
import { providerStyles as baseProviderStyles } from "../core/providerStyles.js"
import type { FullProviderStyles, ProviderNames, ProviderStyle, UseAuthComposableOptions } from "../types.js"

const rc = useRuntimeConfig()
const config = rc.public.auth
const enabledProviders = config.enabledProviders

const { darkMode: isDark } = useInjectedDarkMode()
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

const fullProviderStyles = computed(() => defu(props.providerStyles, baseProviderStyles) as FullProviderStyles)

const styles = computed(() => Object.fromEntries(Object.entries(fullProviderStyles.value).map(([key, value]) => [key, {
	...value,
	style: value?.style
		? {
				backgroundColor: (isDark.value ? value.style.bgDark : value.style.bg) ?? "",
				color: (isDark.value ? value.style.textDark : value.style.text) ?? ""
			}
		: {}
}])) as Partial<Record<ProviderNames, ProviderStyle>>)
</script>
