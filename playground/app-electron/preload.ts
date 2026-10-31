import { createElectronAuthApi } from "@witchcraft/nuxt-auth/electron/preload"
import { createElectronLoggerApi } from "@witchcraft/nuxt-logger/electron/preload"
import { contextBridge, ipcRenderer } from "electron"

import { createTestMultiUserApi } from "./createTestMultiUserApi.js"

import type { PlaygroundWindow } from "../preload-types.js"

contextBridge.exposeInMainWorld("electron", {
	api: {
		...createElectronLoggerApi(ipcRenderer),
		...createElectronAuthApi(ipcRenderer),
		...createTestMultiUserApi(ipcRenderer),
		open: (url: string) => ipcRenderer.invoke("auth.openExternal", url)
	},
	meta: {
		env: {
			LOG_LEVEL: process.env.LOG_LEVEL,
			LOG_WRITE_LEVEL: process.env.LOG_WRITE_LEVEL
		}
	}
} satisfies PlaygroundWindow["electron"])

// optional in real app: setup for potential test-only behavior as regular e2e fixture can't reach an electron window
if (process.env.BAKED_IS_PRODUCTION !== "true" && process.env.TEST === "true") {
	contextBridge.exposeInMainWorld("__IS_TEST", true)
}
