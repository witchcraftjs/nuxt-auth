import { defineConfig, devices } from "@playwright/test"

// < 1.59 has paralization / caching issues
const timeoutMultipler = 3

export default defineConfig({
	globalSetup: "./test/e2e/global-setup.ts",
	reporter: [
		["html", { open: process.env.CI === "true" ? "never" : "on-failure" }]
	],
	projects: [
		{
			name: "web",
			testDir: "test",
			testMatch: ["**/e2e/*.test.ts"]
		},
		{
			name: "electron",
			testDir: "test",
			testMatch: ["electron/**/*.test.ts"],
			// one worker because every launch shares .user-data-dir, which is wiped before each launch
			fullyParallel: false,
			workers: 1
		}
	],
	fullyParallel: true,
	forbidOnly: !!process.env.CI,
	retries: 0,
	workers: 4,
	use: {
		...devices["Desktop Chrome"],
		baseURL: `http://localhost:${process.env.NUXT_PORT}`,
		screenshot: "only-on-failure",
		trace: "on",
		ignoreHTTPSErrors: true,
		actionTimeout: 15000 * timeoutMultipler,
		navigationTimeout: 30000 * timeoutMultipler,
		headless: process.env.CI === "true"
	},

	timeout: 60000 * timeoutMultipler,
	expect: {
		timeout: 10000 * timeoutMultipler
	}
})
