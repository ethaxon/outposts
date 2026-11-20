import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const rootDir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: rootDir,
  resolve: {
    alias: [
      // Mirrors tsconfig.app.json's `@/components/ui/*` mapping; dotted names
      // (e.g. `app-action.component`) are plain files and fall through to `@`.
      {
        find: /^@\/components\/ui\/([a-z-]+)$/,
        replacement: resolve(rootDir, "src/components/ui/$1/src/index.ts"),
      },
      { find: "@", replacement: resolve(rootDir, "src") },
    ],
  },
  test: {
    environment: "node",
    include: ["src/**/*.spec.ts"],
    passWithNoTests: false,
    restoreMocks: true,
    setupFiles: [resolve(rootDir, "src/test-setup.ts")],
  },
});
