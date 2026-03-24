export type RecursiveNonNullable<T> = T extends object
	? {
			[K in keyof T]-?: RecursiveNonNullable<NonNullable<T[K]>>;
		}
	: NonNullable<T>;
