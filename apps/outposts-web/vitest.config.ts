import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const rootDir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: rootDir,
  resolve: {
    alias: {
      "@": resolve(rootDir, "src"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.spec.ts"],
    passWithNoTests: false,
    restoreMocks: true,
    setupFiles: [resolve(rootDir, "src/test-setup.ts")],
  },
});
