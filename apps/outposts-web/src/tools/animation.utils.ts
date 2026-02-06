export const shouldReduceMotion = () => {
	return (
		typeof window !== "undefined" &&
		window.matchMedia(`(prefers-reduced-motion: reduce)`).matches
	);
};
