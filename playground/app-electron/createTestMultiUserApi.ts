import type { ExpectedElectronApi } from "@witchcraft/nuxt-auth/electron/preload"
import type { ipcRenderer as IpcRenderer } from "electron"

export function createTestMultiUserApi(ipcRenderer: typeof IpcRenderer): Pick<ExpectedElectronApi, "users"> {
	return {
		users: {
			list: () => ipcRenderer.invoke("users.list"),
			create: options => ipcRenderer.invoke("users.create", options),
			update: options => ipcRenderer.invoke("users.update", options),
			switchUserAndSoftReload: id => ipcRenderer.invoke("users.switchUserAndSoftReload", id),
			delete: id => ipcRenderer.invoke("users.delete", id)
		}
	}
}
