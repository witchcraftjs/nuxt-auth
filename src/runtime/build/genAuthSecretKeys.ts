import { capitalize } from "@alanscodelog/utils/capitalize"
// this exists because the plugin can't set the keys, they won't show up (am assuming due to safety, user should be explicit about which they need)
/**
 * Generates the auth secret keys for the runtime config in the form `auth{Provider}ClientId` and `auth{Provider}ClientSecret`.
 *
 * Also generates the authSecret key.
 */
// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
export function genAuthSecretKeys(providers: string[]) {
	return {
		authSecret: "",
		...Object.fromEntries(providers.map(provider => [
			[`auth${capitalize(provider)}ClientId`, ""],
			[`auth${capitalize(provider)}ClientSecret`, ""],
		]).flat())
	}
}
