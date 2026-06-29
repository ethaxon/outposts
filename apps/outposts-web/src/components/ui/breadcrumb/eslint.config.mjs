import nx from "@nx/eslint-plugin";
import baseConfig from "../../../../../../eslint.config.mjs";

export default [
  ...nx.configs["flat/angular"],
  ...nx.configs["flat/angular-template"],
  ...baseConfig,
  {
    files: ["**/*.ts"],
    rules: {
      "@angular-eslint/directive-selector": [
        "error",
        {
          type: "attribute",
          prefix: "hlm",
          style: "camelCase",
        },
      ],
      "@angular-eslint/component-selector": "off",
      "@angular-eslint/no-input-rename": "off",
      "@angular-eslint/directive-class-suffix": "off",
      "@angular-eslint/component-class-suffix": "off",
      "@typescript-eslint/naming-convention": [
        "error",
        {
          selector: "classProperty",
          modifiers: ["protected"],
          format: ["camelCase"],
          leadingUnderscore: "require",
        },
      ],
    },
  },
  {
    files: ["**/*.html"],
    // Override or add rules here
    rules: {
      "@angular-eslint/template/interactive-supports-focus": "off",
      "@angular-eslint/template/click-events-have-key-events": "off",
    },
  },
];
