import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const rootDir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: rootDir,
  resolve: {
    alias: [
      {
        find: "@/components/ui/sonner",
        replacement: resolve(rootDir, "src/components/ui/sonner/src/index.ts"),
      },
      {
        find: "@/components/ui/spinner",
        replacement: resolve(rootDir, "src/components/ui/spinner/src/index.ts"),
      },
      {
        find: "@/components/ui/utils",
        replacement: resolve(rootDir, "src/components/ui/utils/src/index.ts"),
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
