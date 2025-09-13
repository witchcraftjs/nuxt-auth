<template>
<div>
	<NuxtUtilsErrorPage :error="error"/>
</div>
</template>

<script setup lang="ts">
import type { NuxtError } from "#app"

/* const props = */ defineProps<{ error: NuxtError }>()
</script>
