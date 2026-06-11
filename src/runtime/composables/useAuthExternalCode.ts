import { unreachable } from "@alanscodelog/utils/unreachable"
import { copy } from "@witchcraft/ui/helpers/copy"
import { onMounted } from "vue"

import {
	navigateTo,
	useRoute
} from "#app"

import { zUriComponentCodec } from "../types.js"

export function useAuthExternalCode() {
	const query = useRoute().query
	const accessToken = query.accessToken
	if (typeof accessToken !== "string") {
		unreachable("No session_token.")
	}
	const deepLinkUrl = zUriComponentCodec.parse(query.deeplinkUri)

	function copyToken() {
		copy(accessToken as string)
	}

	onMounted(() => {
		if (accessToken) {
			void navigateTo(deepLinkUrl, { external: true })
		}
	})

	return {
		accessToken,
		deepLinkUrl,
		copyToken
	}
}
