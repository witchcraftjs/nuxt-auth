import { setupRenderer } from "@better-auth/electron/preload"
import type { ipcRenderer as IpcRenderer } from "electron"

import type { ElectronAuthApi } from "../types.js"
import { exchangeSessionChannel, mockRequestAuthChannel } from "../types.js"
/**
 * Renderer side of the auth bridges: sets up better-auth's own bridges and returns
 * the object to spread into the `electron.api` you expose in the preload.
 */
export function createElectronAuthApi(ipcRenderer: typeof IpcRenderer): ElectronAuthApi {
	setupRenderer()
	return {
		auth: {
			exchangeSession: () => ipcRenderer.invoke(exchangeSessionChannel),
			mockRequestAuth: options => ipcRenderer.invoke(mockRequestAuthChannel, options),
			betterAuth: {
				authenticate: data => ipcRenderer.invoke("better-auth:authenticate", data),
				requestAuth: options => ipcRenderer.invoke("better-auth:requestAuth", options)
			}
		}
	}
}
