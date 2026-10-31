import { expect, test as base } from "@playwright/test"

export const test = base.extend({
	browser: async ({ browser }, use) => {
		const newContext = browser.newContext.bind(browser)
		browser.newContext = async options => {
			const context = await newContext(options)
			await context.addInitScript(() => {
				(window as any).__IS_TEST = true
			})
			return context
		}
		await use(browser)
	}
})

export { expect }
