import { githubProviderStyle } from "./providers/github.js"
import { googleProviderStyle } from "./providers/google.js"

import type { ProviderStyle } from "../types.js"

// import TwitterLogo from "~icons/fa6-brands/x-twitter"
// import FacebookLogo from "~icons/logos/facebook"

//
// export const facebookProviderStyle = {
// 	name: "Facebook",
// 	logo: FacebookLogo,
// 	class: "bg-white text-[#006aff] dark:bg-[#006aff] dark:text-white",
// }

// export const twitterProviderStyle = {
// 	name: "Twitter",
// 	logo: TwitterLogo,
//    class: "bg-white text-[#1da1f2] dark:bg-[#1da1f2] dark:text-white",
// }

export const providerStyles: Record<string, ProviderStyle> = {
	github: githubProviderStyle,
	google: googleProviderStyle
}
