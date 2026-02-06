const nx = require("@nx/eslint-plugin");
const baseConfig = require("../../eslint.config.cjs");

module.exports = [
	...baseConfig,
	...nx.configs["flat/angular"],
	...nx.configs["flat/angular-template"],
	{
		files: ["**/*.ts"],
		rules: {
			"@angular-eslint/directive-selector": [
				"error",
				{
					type: "attribute",
					prefix: "app",
					style: "camelCase",
				},
			],
			"@angular-eslint/prefer-standalone": "off",
			"@angular-eslint/component-selector": [
				"error",
				{
					type: "element",
					prefix: "app",
					style: "kebab-case",
				},
			],
			"@typescript-eslint/no-explicit-any": "off",
			"@typescript-eslint/ban-ts-comment": "off",
			"@angular-eslint/no-input-rename": "warn",
			"@typescript-eslint/no-unused-vars": [
				"warn",
				{
					args: "all",
					argsIgnorePattern: "^_",
					caughtErrors: "all",
					caughtErrorsIgnorePattern: "^_",
					destructuredArrayIgnorePattern: "^_",
					varsIgnorePattern: "^_",
					ignoreRestSiblings: true,
				},
			],
		},
	},
	{
		files: ["**/*.html"],
		// Override or add rules here
		rules: {},
	},
];
