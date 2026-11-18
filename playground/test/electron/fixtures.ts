import { launchElectron } from "@witchcraft/nuxt-electron/electron/test"
import { existsSync } from "node:fs"
import { fileURLToPath } from "node:url"

import { localhostUrl } from "../../localhostUrl.js"

const playgroundDir = fileURLToPath(new URL("../..", import.meta.url))
/** One profile for every launch, in the repo (gitignored) so it can be inspected. */
const userDataDir = fileURLToPath(new URL("../../.user-data-dir", import.meta.url))
/** The production build of the playground app, made with `pnpm build:electron:no-pack`. */
const mainEntry = fileURLToPath(new URL("../../.dist/electron/build/main.mjs", import.meta.url))

if (!existsSync(mainEntry)) {
	throw new Error(`Missing ${mainEntry}, run \`pnpm build:electron:no-pack\` in playground first.`)
}
if (process.env.TEST_ELECTRON_DEV && !process.env.NUXT_PORT) {
	throw new Error("NUXT_PORT is not set, the test server port must be known to point the app at it.")
}


export const test = launchElectron({
	appDir: playgroundDir,
	userDataDir,
	serverUrl: localhostUrl(),
	bundlePrefix: "app://bundle/",
	useDevMode: process.env.TEST_ELECTRON_DEV === "1"
})

export { expect } from "@playwright/test"
export type { ElectronApplication, Locator, Page } from "@playwright/test"
