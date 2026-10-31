import { setup, url } from "@nuxt/test-utils/e2e"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

await setup({
	rootDir: fileURLToPath(new URL("../..", import.meta.url)),
	host: `http://localhost:${process.env.NUXT_PORT}`
})

const tag = Date.now().toString(36)
const username = (suffix: string) => `u${tag}${suffix}`

async function devBypassCallback(params: Record<string, string>) {
	const query = new URLSearchParams(params)
	return fetch(url(`/api/auth/callback/github?${query}`), { redirect: "manual" })
}

function sessionCookie(res: Response) {
	const header = res.headers.getSetCookie().find(cookie => cookie.startsWith("better-auth.session_token="))
	return header?.split(";")[0] ?? ""
}

async function getSession(cookie: string) {
	const res = await fetch(url("/api/auth/get-session"), { headers: { cookie } })
	return res.json() as Promise<{ user: Record<string, any> } | null>
}

describe("dev bypass", { tags: ["server"] }, () => {
	it("bypass user (new) => register page, still unregistered", async () => {
		// a user who does not bypass registration has no username yet, they pick one when they register
		const res = await devBypassCallback({ devBypass: "true" })

		expect(res.status).toBe(302)
		expect(res.headers.get("location")).toBe("/auth/register")

		const cookie = sessionCookie(res)

		expect(cookie).not.toBe("")

		const session = await getSession(cookie)

		expect(session?.user.username).toBeNull()
		expect(session?.user.isRegistered).toBe(false)
		expect(session?.user.name).toBe(session?.user.id)
	})

	it("bypass user (registered) => authed page", async () => {
		const name = username("reg")
		const res = await devBypassCallback({ devBypass: "true", username: name, devBypassRegistration: "true" })

		expect(res.status).toBe(302)
		expect(res.headers.get("location")).toBe("/authed")

		const session = await getSession(sessionCookie(res))

		expect(session?.user.username).toBe(name)
		expect(session?.user.isRegistered).toBe(true)
	})

	it("bypass user (invalid username) => rejected", async () => {
		// the app's own username schema applies, the mock cannot hand it a name it would refuse
		const res = await devBypassCallback({ devBypass: "true", username: "ab", devBypassRegistration: "true" })

		expect(res.status).toBe(400)
	})

	it("falls back to post login for unknown deeplinks", async () => {
		const name = username("deep")
		const res = await devBypassCallback({ devBypass: "true", username: name, devBypassRegistration: "true", deeplink: "browser" })

		expect(res.status).toBe(302)
		expect(res.headers.get("location")).toBe("/authed")
	})
})

describe("registration", { tags: ["server"] }, () => {
	it("username update => username saved, user marked registered", async () => {
		const login = await devBypassCallback({ devBypass: "true" })
		const cookie = sessionCookie(login)

		expect(cookie).not.toBe("")

		const name = username("taken")
		const update = await fetch(url("/api/auth/update-user"), {
			method: "POST",
			headers: { "content-type": "application/json", cookie, origin: new URL(url("/")).origin },
			body: JSON.stringify({ username: name })
		})

		expect(update.status).toBe(200)

		const session = await getSession(cookie)

		expect(session?.user.username).toBe(name)
		expect(session?.user.isRegistered).toBe(true)
	})
})

describe("username availability", { tags: ["server"] }, () => {
	it("returns true for a free name", async () => {
		const res = await fetch(url(`/api/auth/username/valid?username=${username("free")}`))

		expect(await res.json()).toBe(true)
	})

	it("returns false for a taken name", async () => {
		const name = username("used")
		await devBypassCallback({ devBypass: "true", username: name, devBypassRegistration: "true" })

		const res = await fetch(url(`/api/auth/username/valid?username=${name}`))

		expect(await res.json()).toBe(false)
	})

	it("returns false for an invalid name", async () => {
		const res = await fetch(url("/api/auth/username/valid?username=ab"))

		expect(await res.json()).toBe(false)
	})
})
