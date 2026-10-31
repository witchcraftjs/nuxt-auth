<template>
<AuthExternalCallback
	:authenticate="exchangeAndPersist"
	:request-external-auth="onRequestExternalAuth"
/>
</template>

<script setup lang="ts">
async function onRequestExternalAuth(options: { provider?: string }): Promise<void> {
	await window.electron.api.auth.betterAuth.requestAuth(options)
}

async function exchangeAndPersist(token: string): Promise<void> {
	// normally the browser opens the deeplink and electron main does this token exchange
	// but it it can't and user must paste it locally, we need to the send it to better auth on main somehow
	await window.electron.api.auth.betterAuth.authenticate({ token })
	// then we can try exchanging for a proper session
	await window.electron.api.auth.exchangeSession()
}
</script>
