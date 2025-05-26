import "dotenv/config";
import { defineConfig } from "drizzle-kit";

import { env } from "./lib/env";

export default defineConfig({
  out: "./db/migrations",
  schema: "./db/schema.ts",
  dialect: "postgresql",
  dbCredentials: {
    url: env.DATABASE_URL,
  },
});
