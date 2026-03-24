const { createGlobPatternsForDependencies } = require("@nx/angular/tailwind");
const { join } = require("node:path");
const plugin = require("tailwindcss/plugin");

/** @type {import('tailwindcss').Config} */
module.exports = {
	content: [
		join(__dirname, "src/**/!(*.stories|*.spec).{ts,html}"),
		...createGlobPatternsForDependencies(__dirname),
	],
	darkMode: ["selector", '[class="p-dark"]'],
	plugins: [
		require("tailwindcss-primeui"),
		plugin(function outpostsThemePlugin({ addUtilities }) {
			addUtilities({
				".bg-surface-auto-50": {
					"@apply bg-surface-50 dark:bg-surface-950": {},
				},
			});
		}),
	],
	// corePlugins: { preflight: false },
	theme: {
		screens: {
			sm: "576px",
			md: "768px",
			lg: "992px",
			xl: "1200px",
			"2xl": "1920px",
		},
	},
};
