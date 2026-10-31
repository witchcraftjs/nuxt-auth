import type { ElectronUserEntry } from "@witchcraft/nuxt-auth/electron/preload"
import { userStorageKey } from "@witchcraft/nuxt-auth/types"
import { app, type BrowserWindow, ipcMain, session } from "electron"
import { existsSync } from "node:fs"
import fs from "node:fs/promises"
import path from "node:path"

/**
 * Crude, test-only multi-user setup: persists users as directories, and registers the `users.*` bridges.
 *
 * One source of truth, `<userData>/users/`, scanned into memory.
 *
 * Dir names carry the kind, `<id>` for external users and `local-<id>` for local ones, each holding a `username` file.
 *
 * A real app has its own registry, folder layout and per-user store. This harness exists so the login page has something to list, create and remove.
 */
export function setupTestMultiUser({
	saveLocalUserSession,
	setActiveUser,
	reopenWindow
}: {
	/** For writeUserActive, writes the persisted active user into a window. */
	saveLocalUserSession: (win: BrowserWindow, authUser: unknown) => Promise<void>
	/** Called with the user being switched to, undefined to go back to the default session. */
	setActiveUser: (id: string | undefined) => void
	/** Opens the window in the new user's partition, then closes the previous one. */
	reopenWindow: () => Promise<void>
}) {
	const activeUserFile = path.join(app.getPath("userData"), "active-user.json")
	const usersDir = path.join(app.getPath("userData"), "users")

	const dirOf = (id: string, isLocal: boolean): string => (isLocal ? `local-${id}` : id)

	function parseDir(directory: string): { id: string, isLocal: boolean } | undefined {
		const isLocal = directory.startsWith("local-")
		const id = isLocal ? directory.slice("local-".length) : directory
		if (!id) return undefined
		return { id, isLocal }
	}

	async function scanAndListUsers(): Promise<ElectronUserEntry[]> {
		if (!existsSync(usersDir)) return []
		const dirents = await fs.readdir(usersDir, { withFileTypes: true })
		if (!dirents) return []
		const entries: ElectronUserEntry[] = []
		for (const dirent of dirents) {
			if (!dirent.isDirectory()) continue
			const parsed = parseDir(dirent.name)
			if (!parsed) continue
			// the directory name carries the id, the file is only the label, and a real username is
			// never empty so a blank file means the user has none yet
			const raw = await fs.readFile(path.join(usersDir, dirent.name, "username"), "utf8").catch(() => "")
			entries.push({
				directory: dirent.name,
				username: raw === "" ? undefined : raw,
				isLocal: parsed.isLocal,
				id: parsed.id
			})
		}
		return entries
	}

	async function ensureUserDir({ id, username, isLocal }: { id: string, username: string | null | undefined, isLocal: boolean }): Promise<string> {
		const directory = dirOf(id, isLocal)
		const directoryPath = path.join(usersDir, directory)
		await fs.mkdir(directoryPath, { recursive: true })
		// an external user has no username until it registers, an empty file says exactly that
		await fs.writeFile(path.join(directoryPath, "username"), username ?? "", "utf8")
		return directory
	}

	async function readActiveUser(): Promise<string | undefined> {
		if (!existsSync(activeUserFile)) return undefined
		const raw = await fs.readFile(activeUserFile, "utf8")
		if (!raw) return undefined
		return (JSON.parse(raw) as { id?: unknown }).id as string | undefined
	}

	/** Persists the active user id, so a relaunch opens in that user's partition. */
	async function persistActiveUser(id: string | undefined): Promise<void> {
		setActiveUser(id)
		await fs.mkdir(path.dirname(activeUserFile), { recursive: true })
		await fs.writeFile(activeUserFile, JSON.stringify({ id }), "utf8")
	}

	/** Records an external user after its login is persisted, so `users.list` sees it. */
	async function recordExternalUser({ id, username }: { id: string, username: string | null | undefined }): Promise<void> {
		await ensureUserDir({ id, username, isLocal: false })
	}

	ipcMain.handle("users.switchUserAndSoftReload", async (_event, id: string | undefined) => {
		await persistActiveUser(id)
		await reopenWindow()
	})

	ipcMain.handle("users.list", async () => scanAndListUsers())

	ipcMain.handle("users.create", async (_event, { id, username }: { id: string, username: string }) => {
		await ensureUserDir({ id, username, isLocal: true })
		// the button is "create and switch", same as the browser plugin
		await persistActiveUser(id)
		await reopenWindow()
	})

	ipcMain.handle("users.update", async (_event, { id, patch }: { id: string, patch: { username?: string, name?: string, image?: string | null } }) => {
		const entries = await scanAndListUsers()
		const user = entries.find(entry => entry.id === id)
		if (!user) return
		if (patch.username !== undefined && patch.username !== user.username) {
			await fs.writeFile(path.join(usersDir, user.directory, "username"), patch.username, "utf8")
		}
		if (await readActiveUser() !== id) return
		// the partition and the window's stored user both follow the id, but the cached
		// username changed, so reopen to keep them in step
		if (patch.username !== undefined) await reopenWindow()
	})

	ipcMain.handle("users.delete", async (_event, id: string) => {
		const entries = await scanAndListUsers()

		const user = entries.find(entry => entry.id === id)
		if (!user) return

		// without this, reopening the user resurrects them from the storage left in their partition
		await session.fromPartition(`persist:playground:${id}`).clearStorageData()
		await fs.rm(path.join(usersDir, user.directory), { recursive: true, force: true })
		if (await readActiveUser() !== id) return

		await persistActiveUser(undefined)
		await reopenWindow()
	})

	/**
	 * When a user is a local user, writes the active user entry to the window.
	 */
	async function restoreLocalUserSession(win: BrowserWindow): Promise<void> {
		const id = await readActiveUser()
		if (!id) return

		const user = await scanAndListUsers().then(users => users.find(user => user.id === id))
		if (!user || !user.isLocal) return

		const hasData = await win.webContents.executeJavaScript(`localStorage.getItem(${JSON.stringify(userStorageKey)})`)
		if (hasData) return

		const now = new Date()
		await saveLocalUserSession(win, {
			id: user.id,
			email: "",
			emailVerified: false,
			name: user.username,
			image: null,
			username: user.username,
			isRegistered: true,
			createdAt: now.toISOString(),
			updatedAt: now.toISOString(),
			type: "local"
		})
	}

	return { readActiveUser, restoreLocalUserSession, scanAndListUsers, recordExternalUser }
}
