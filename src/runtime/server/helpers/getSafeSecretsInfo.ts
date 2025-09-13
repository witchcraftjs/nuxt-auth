import { capitalize } from "@alanscodelog/utils/capitalize"
import { isBlank } from "@alanscodelog/utils/isBlank"

import { useRuntimeConfig } from "#imports"

export function getSafeSecretsInfo(): {
	allowedSecrets: string[]
	secretsKeysPassed: string[]
} {
	const rc = useRuntimeConfig()
	const auth = rc.public.auth
	const allowedSecrets = auth.enabledProviders.flatMap(provider => [`auth${capitalize(provider)}ClientId`, `auth${capitalize(provider)}ClientSecret`])
	const secretsKeysPassed = Object.keys(rc).filter(key =>
		allowedSecrets.includes(key as any)
		&& rc[key] !== undefined
		&& !isBlank(rc[key] as any))
	return { allowedSecrets, secretsKeysPassed }
}
