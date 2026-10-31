import { createAuthMiddleware } from "@witchcraft/nuxt-auth/server/utils/createAuthMiddleware"

import { useServerLogger } from "#imports"

import { auth } from "../auth.js"

export default createAuthMiddleware(auth, useServerLogger())

