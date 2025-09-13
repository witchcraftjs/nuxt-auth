import type {
	JwtPayload,
	VerifyOptions
} from "jsonwebtoken"
import jwt from "jsonwebtoken"

/** Promisified version of jsonwebtoken.verify. */
export async function verifyJwt<T extends Record<string, any>>(
	token: string | undefined,
	secret: string,
	opts: Partial<VerifyOptions & { complete: true }> = {}
): Promise<T & JwtPayload> {
	if (!token) {
		throw new Error("Missing token.")
	}
	return new Promise((resolve, reject) => {
		jwt.verify(token, secret, opts, (err, decoded) => {
			if (err) {
				reject(err)
			} else {
				if (typeof decoded !== "object") {
					reject(new Error(`Decoded was of wrong type. Expected object, got ${typeof decoded}.`))
					return
				}
				resolve(decoded as any)
			}
		})
	})
}
