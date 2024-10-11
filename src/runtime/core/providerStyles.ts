import { githubProviderStyle } from "./providers/github.js"
import { googleProviderStyle } from "./providers/google.js"

import type { ProviderStyle } from "../types.js"

// import TwitterLogo from "~icons/fa6-brands/x-twitter"
// import FacebookLogo from "~icons/logos/facebook"

//
// export const facebookProviderStyle = {
// 	name: "Facebook",
// 	logo: FacebookLogo,
// 	style: {
// 		bg: "#fff",
// 		text: "#006aff",
// 		bgDark: "#006aff",
// 		textDark: "#fff"
// 	},
// }

// export const twitterProviderStyle = {
// 	name: "Twitter",
// 	logo: TwitterLogo,
// 	style: {
// 		bg: "#fff",
// 		text: "#1da1f2",
// 		bgDark: "#1da1f2",
// 		textDark: "#fff"
// 	}
// }

export const providerStyles: Record<string, ProviderStyle> = {
	github: githubProviderStyle,
	google: googleProviderStyle,
}

