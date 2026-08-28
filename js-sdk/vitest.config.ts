import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // The wasm module is instantiated once per worker; the suites are
    // independent, so parallel files are fine.
    testTimeout: 30_000,
  },
});
