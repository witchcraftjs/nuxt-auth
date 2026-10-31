import { copyToClipboard } from "@alanscodelog/utils/copyToClipboard"
import { computed, onUnmounted, ref } from "vue"

import {
	useRuntimeConfig
} from "#app"

import { useAuth } from "../composables/useAuth.js"

export function useAuthExternalCode() {
	const config = useRuntimeConfig().public.auth as any
	const auth = useAuth()

	const client = auth.client

	const code = ref<string | undefined>(client.electron?.getAuthorizationCode() ?? undefined)
	let redirectInterval: NodeJS.Timeout | undefined
	if (import.meta.client) redirectInterval = client.ensureElectronRedirect()

	const deepLinkUrl = computed(() => {
		const scheme = config.deeplinkSchemes?.electron
		if (!code.value || !scheme) return undefined
		return `${scheme}://${config.authRoutes.deeplink.replace(/^\//, "")}#token=${code.value}`
	})

	onUnmounted(() => {
		if (redirectInterval) clearInterval(redirectInterval)
	})

	function copyToken() {
		copyToClipboard(code.value ?? "")
	}

	return {
		accessToken: code,
		deepLinkUrl,
		copyToken
	}
}
