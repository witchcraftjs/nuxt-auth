import type { SignOptions } from "jsonwebtoken"
import jwt from "jsonwebtoken"

/** Promisified version of jsonwebtoken.sign. */
export async function signJwt(
	payload: any,
	secret: string,
	opts: Partial<SignOptions | { algorithm: "none" }> = {}
): Promise<string> {
	return new Promise((resolve, reject) => {
		jwt.sign(payload, secret, opts, (err, token) => {
			if (err) {
				reject(err)
			} else {
				if (typeof token !== "string") {
					reject(new Error(`Token was of wrong type. Expected string, got ${typeof token}.`))
					return
				}
				resolve(token)
			}
		})
	})
}
