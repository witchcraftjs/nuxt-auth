<template>
<NuxtLayout>
	<NuxtPage/>
</NuxtLayout>
</template>

<script lang="ts" setup>
// the renderer logger forwards to main, see @witchcraft/nuxt-logger's electron docs
if (import.meta.client && "electron" in window) useLogger({ redirectTo: "electron", redirectAll: true })
setupElectronMainToRendererLogging()
</script>
