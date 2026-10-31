import { auth } from "../../auth.js"

export default defineEventHandler(event => {
	return auth.handler(toWebRequest(event))
})
