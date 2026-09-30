import path from "node:path";
import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";

// Vite doesn't know wrangler's `[[rules]] type = "Text"`; mirror it here.
const textModules = {
  name: "text-modules",
  transform(code, id) {
    if (id.endsWith(".txt")) return { code: `export default ${JSON.stringify(code)};`, map: null };
  },
};

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
  return {
    plugins: [
      textModules,
      cloudflareTest({
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          bindings: { TEST_MIGRATIONS: migrations, DEV_ALLOW_CERT_HEADER: "1" },
        },
      }),
    ],
    test: {
      setupFiles: ["./test/setup.js"],
    },
  };
});
