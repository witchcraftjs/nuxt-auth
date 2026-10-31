import { expect, test } from "./fixtures.js"

test("app page cannot store a cookie", async ({ app }) => {
	// bundle-only: http(s) origins can store cookies, only app:// cannot
	test.skip(process.env.TEST_ELECTRON_DEV === "1", "needs the app:// bundle window")
	const result = await app.evaluate(async electron => {
		const win = electron.BrowserWindow.getAllWindows()[0]
		if (!win) return "no window"
		const ses = win.webContents.session
		const appPage = await ses.cookies
			.set({ url: "app://bundle/", name: "probe", value: "abc" })
			.then(() => "ok")
			.catch(() => "rejected")
		const stored = await ses.cookies.get({ name: "probe" })
		return `${appPage}/${stored.length}`
	})

	// chromium only stores cookies for http(s) schemes, whatever privileges the scheme has
	expect(result).toBe("rejected/0")
})
