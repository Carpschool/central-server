import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
/** Env holds ONLY these. Everything else lives in the DB (settings) or the data/ volume. */
export const ENV_KEYS = ["PORT", "NODE_ENV", "MONGO_URI", "CLERK_PUBLISHABLE_KEY", "CLERK_SECRET_KEY"] as const;
export function required(name: (typeof ENV_KEYS)[number]): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error("Missing required environment variable: " + name);
  return value;
}
export function validateEnv() {
  required("MONGO_URI");
  required("CLERK_SECRET_KEY");
}
let dir = resolve("data");
/** Persistent volume for the signing key (mount it in Docker). Tests point it elsewhere. */
export function setDataDir(d: string) { dir = d; }
export const dataDir = () => dir;
export function persisted(name: string, make: () => string): string {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const p = join(dir, name);
  if (!existsSync(p)) writeFileSync(p, make(), { mode: 0o600 });
  if ((statSync(p).mode & 0o077) !== 0) chmodSync(p, 0o600);
  return readFileSync(p, "utf8");
}
