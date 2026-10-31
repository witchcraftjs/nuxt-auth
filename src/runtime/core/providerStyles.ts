import GithubLogo from "~icons/logos/github-icon"
import GoogleLogo from "~icons/logos/google-icon"

import type { ProviderStyle } from "../types.js"

export const providerStyles: Record<string, ProviderStyle> = {
	github: {
		name: "Github",
		logo: GithubLogo,
		class: "bg-white text-black dark:bg-black dark:text-white"
	},
	google: {
		name: "Google",
		logo: GoogleLogo,
		class: "bg-white text-black dark:bg-black dark:text-white"
	}
}
