import * as z from "zod";

export const envSchema = z.object({
  SESSION_SECRET: z.string(),
  DATABASE_URL: z.string().url(),
});

// eslint-disable-next-line node/no-process-env
export const env = envSchema.parse(process.env);
