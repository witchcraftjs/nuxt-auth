import { migrate } from "#postgres"

export default defineNitroPlugin(() => {
	// #awaiting https://github.com/nitrojs/nitro/issues/915
	void migrate({ generateMigration: true })
})
