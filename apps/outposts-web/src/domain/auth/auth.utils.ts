export function parseScope(scope?: string): string[] {
	return typeof scope === "string"
		? scope
				.split(/\s+/g)
				.map((s) => s.trim())
				.filter(Boolean)
		: [];
}
