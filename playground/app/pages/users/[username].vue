<template>
<div class="p-6">
	<div>
		User Profile
	</div>
	<div>
		Server user: {{ serverUser }}
	</div>
	<div>
		Client user: {{ clientUser }}
	</div>
	<div>
		Rendered by: {{ renderedBy }}
	</div>
</div>
</template>

<script lang="ts" setup>
const { user } = useAuth()
const { username } = useRoute().params

// this check *will* run on the server, except on external apps which pre-render it, they will error client side
// it should not be possible to "grab" another user's data, even if this check wasn't here as the auth doesn't allow this
// on your end you should always be gating user-specific APIs server side to check they are for the proper users anyways
// error is mostly a nicety
if (user.value && user.value.username !== username) {
	throw createError({ statusCode: 404, statusMessage: "Not found", fatal: true })
}

const serverUser = useState("users-server-user", () => {
	return import.meta.server ? user.value?.username ?? "none" : "not rendered on the server"
})
const clientUser = computed(() => user.value?.username ?? "none")
const renderedBy = useState("users-rendered-by", () => import.meta.server ? "server" : "client")

definePageMeta({
	middleware: "authProtected",
	auth: {
		only: "authenticated-registered",
		redirectTo: "$login",
		// to enable local users
		disableServerRedirect: true
	}
})
</script>
