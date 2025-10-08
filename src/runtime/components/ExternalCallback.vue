<template>
<div class="flex flex-col gap-4">
	<template v-if="authUri">
		<div class="text-xl text-center">
			Authorize
		</div>
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
		<form
			class="flex flex-col gap-4"
			@submit.prevent="authorize(manualAccessToken)"
		>
			<WInputDeprecated
				placeholder="Paste Code Here"
				v-model="manualAccessToken"
				@update:model-value="error=undefined"
			/>
			<div
				v-if="error"
				class="border-2 border-red-500 bg-red-100 dark:bg-red-900 rounded-md p-2"
			>
				{{ error }}
			</div>
			<WButton
				:disabled="!manualAccessToken || manualAccessToken.length === 0"
				type="submit"
			>
				Submit
			</WButton>
			<WButton
				type="button"
				@click="cancel"
			>
				Cancel
			</WButton>
		</form>
	</template>
	<template v-else>
		<div class="text-xl text-center">
			Authorizing...
		</div>
		<WButton @click="authorize(initialAccessToken)">
			Retry
		</WButton>
	</template>
</div>
</template>

<script lang="ts" setup>
import z from "zod"

import { useRuntimeConfig } from "#app"
import {
	navigateTo,
	ref,
	useRoute } from "#imports"

import { zExternalCallbackPageQuery } from "../types.js"


const props = defineProps<{
	saveSession: (accessToken: string) => Promise<void>
	successPath?: string
	cancelPath?: string
}>()

const rc = useRuntimeConfig()
const query = useRoute().query


const parsedQuery = zExternalCallbackPageQuery.safeParse(query)
if (parsedQuery.error) throw new Error(z.prettifyError(parsedQuery.error))
const initialAccessToken = "accessToken" in parsedQuery.data ? parsedQuery.data.accessToken : undefined
const authUri = "authUri" in parsedQuery.data ? parsedQuery.data.authUri : undefined

if (initialAccessToken) {
	void authorize(initialAccessToken, true)
}

const manualAccessToken = ref("")
const error = ref()

async function authorize(
	accessToken?: string,
	initial: boolean = false
) {
	if (!accessToken || accessToken.length === 0) {
		if (!initial) {
			error.value = "No code provided."
		}
		return
	}
	const res = await props.saveSession(accessToken)
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
