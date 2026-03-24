import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "eslint/config";
import eslint from "@eslint/js";
import angular from "angular-eslint";
import oxlint from "eslint-plugin-oxlint";
import tseslint from "typescript-eslint";

const tsconfigRootDir = dirname(fileURLToPath(import.meta.url));

const ignores = [
  "**/dist",
  "**/node_modules",
  "**/.angular",
  "**/.nx",
  "**/coverage",
  "**/target",
  "**/*.d.ts",
  "apps/outposts-web/src/assets/**",
  "postgres/data/**",
];

const jsFiles = ["**/*.{js,mjs}"];
const commonJsFiles = ["**/*.cjs", "transloco.config.js"];
const tsFiles = ["**/*.{ts,mts,cts}"];
const angularTsFiles = ["apps/outposts-web/src/**/*.ts"];
const angularTsIgnores = [
  "apps/outposts-web/src/**/*.server.ts",
  "apps/outposts-web/src/server.ts",
  "apps/outposts-web/src/main.server.ts",
  "apps/outposts-web/src/app/*.server.ts",
];
const templateFiles = ["apps/outposts-web/src/**/*.component.html"];
const oxlintFiles = ["**/*.{js,cjs,mjs}"];

const commonJsGlobals = {
  __dirname: "readonly",
  exports: "writable",
  module: "readonly",
  process: "readonly",
  require: "readonly",
};

const tsRules = {
  "@typescript-eslint/ban-ts-comment": "off",
  "@typescript-eslint/no-explicit-any": "off",
  "@typescript-eslint/no-unused-vars": [
    "error",
    {
      argsIgnorePattern: "^_",
      caughtErrorsIgnorePattern: "^_",
      varsIgnorePattern: "^_",
    },
  ],
};

const angularRules = {
  "@angular-eslint/no-input-rename": "off",
  "@angular-eslint/prefer-standalone": "off",
};

export default defineConfig(
  {
    ignores,
  },
  {
    files: jsFiles,
    extends: [eslint.configs.recommended],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
    },
  },
  {
    files: commonJsFiles,
    extends: [eslint.configs.recommended],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "commonjs",
      globals: commonJsGlobals,
    },
  },
  {
    files: tsFiles,
    extends: [eslint.configs.recommended, ...tseslint.configs.recommended],
    rules: tsRules,
  },
  {
    files: angularTsFiles,
    ignores: angularTsIgnores,
    extends: [...angular.configs.tsRecommended],
    processor: angular.processInlineTemplates,
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir,
      },
    },
    rules: angularRules,
  },
  {
    files: templateFiles,
    extends: [...angular.configs.templateRecommended, ...angular.configs.templateAccessibility],
  },
  ...oxlint.configs["flat/recommended"].map((config) => ({
    ...config,
    files: oxlintFiles,
  })),
);
