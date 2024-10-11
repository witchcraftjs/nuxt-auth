export function logSafeRoute(route: string): string {
	return route.split("?")[0]
}
