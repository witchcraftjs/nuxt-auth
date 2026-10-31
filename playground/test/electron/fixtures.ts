import { type ElectronApplication, expect, type Page, test as base } from "@playwright/test"

import { launchApp } from "./utils.js"

export const test = base.extend<{
	app: ElectronApplication
	page: Page
	getPageFromWindow: () => Promise<Page>
}>({
	// eslint-disable-next-line no-empty-pattern
	app: async ({}, use) => {
		const { app, close } = await launchApp()
		await use(app)
		await close()
	},
	page: async ({ app }, use) => {
		await use(await app.firstWindow())
	},
	getPageFromWindow: async ({ app }, use) => {
		// the first window is not a reopen, and its event has already fired by the time this runs
		const first = await app.firstWindow()
		const pending: Page[] = []
		const waiting: (() => void)[] = []
		app.on("window", window => {
			if (window === first) return
			pending.push(window)
			waiting.shift()?.()
		})

		await use(async () => {
			// the event can have fired before the caller asks, so the queue is the only source, never waitForEvent
			if (pending.length === 0) await new Promise<void>(resolve => waiting.push(resolve))
			const next = pending.shift()!
			await next.waitForLoadState()

			// the app closes the old window asynchronously, so it can still be listed while the new one loads
			await expect.poll(() => app.evaluate(electron => electron.BrowserWindow.getAllWindows().length)).toBe(1)

			return next
		})
	}
})

export { expect }
export type { ElectronApplication, Locator, Page } from "@playwright/test"
