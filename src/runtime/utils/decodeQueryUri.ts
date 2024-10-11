import { type LocationQueryValue } from "vue-router"

export function decodeQueryUri(queryValueryValue: string | LocationQueryValue | LocationQueryValue[]): string | undefined {
	if (typeof queryValueryValue !== "string") return undefined
	return decodeURIComponent(queryValueryValue)
}
