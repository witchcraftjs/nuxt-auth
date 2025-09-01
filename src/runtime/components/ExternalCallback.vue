<template>
<div class="flex flex-col gap-4">
	<template v-if="authUri">
		<div class="text-xl text-center">Authorize</div>
		<div class="text-lg text-center">
			If you are not redirected automatically, open following URL and paste the code given:
			<NuxtLink
				class="link-like underline"
				:href="authUri"
				target="_blank"
			>
				{{ authUri }}
			</NuxtLink>
		</div>
		<WInputDeprecated
			placeholder="Paste Code Here"
			v-model="accessToken"
			@update:model-value="error=undefined"
		/>
		<div v-if="error" class="border-2 border-red-500 bg-red-100 dark:bg-red-900 rounded-md p-2">
			{{ error }}
		</div>
		<WButton
			:disabled="!accessToken || accessToken.length === 0"
			@click="authorize(accessToken)"
		>
			Submit
		</WButton>
		<WButton @click="cancel">Cancel</WButton>
	</template>
	<template v-else>
		<div class="text-xl text-center">Authorizing...</div>
		<WButton @click="authorize(initialAccessToken)">Retry</WButton>
	</template>
</div>
</template>
<script lang="ts" setup>
import { unreachable } from "@alanscodelog/utils/unreachable"

import { useRuntimeConfig } from "#app"
import {
	navigateTo,
	ref,
	useRoute } from "#imports"

import { decodeQueryUri } from "../utils/decodeQueryUri.js"

const props = defineProps<{
	saveSession: (token: string) => Promise<void>
	successPath?: string
	cancelPath?: string
}>()


const rc = useRuntimeConfig()
const query = useRoute().query

const initialAccessToken = query.access_token
const authUri = decodeQueryUri(query.authUri)
if (!authUri && typeof initialAccessToken !== "string") {
	throw new Error(`access_token parameter is not a string, got query: ${JSON.stringify(query)}`)
}
if (!authUri && !initialAccessToken) {
	unreachable("Server should have passed authUri or access_token.")
}

if (typeof initialAccessToken === "string") {
	void authorize(initialAccessToken, true)
}

const accessToken = ref("")
const error = ref()

async function authorize(
	token?: string,
	initial: boolean = false
) {
	if (!token || token.length === 0) {
		if (!initial) {
			error.value = "No code provided."
		}
		return
	}
	const res = await props.saveSession(token)
		.catch(err => {
			error.value = err.message
			return err
		})
	if (!(res instanceof Error)) {
		await navigateTo(props.successPath ?? rc.public.auth.authRoutes.postRegisteredLogin)
	}
}
async function cancel() {
	await navigateTo(props.cancelPath ?? rc.public.auth.authRoutes.login)
}

</script>
