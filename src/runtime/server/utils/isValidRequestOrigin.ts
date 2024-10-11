export function isValidRequestOrigin(origin: string | null, allowedDomains: string[] = []): boolean {
	if (!origin || allowedDomains.length === 0) {
		return false
	}
	const originHost = safeUrl(origin)?.host ?? null
	if (!originHost) {
		return false
	}
	for (const domain of allowedDomains) {
		let host: string | null
		if (domain.startsWith("http://") || domain.startsWith("https://")) {
			host = safeUrl(domain)?.host ?? null
		} else {
			host = safeUrl(`https://${domain}`)?.host ?? null
		}
		if (originHost === host) {
			return true
		}
	}
	return false
}

function safeUrl(url: URL | string): URL | null {
	try {
		return new URL(url)
	} catch {
		return null
	}
}
