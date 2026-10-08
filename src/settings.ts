import { BadRequestException, Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model, Schema } from "mongoose";
export const SettingSchema = new Schema({ key: { type: String, unique: true, required: true }, value: Schema.Types.Mixed });
export type CentralSettings = {
  /** Public origin of this central server; used as JWT issuer. */
  publicUrl: string;
  /** Web app origins: CORS + Clerk authorized parties. */
  corsOrigins: string[];
  /** Svix secret for the Clerk webhook (write-only). */
  webhookSecret: string;
};
const EMPTY: CentralSettings = { publicUrl: "", corsOrigins: [], webhookSecret: "" };
export function origin(u: string, allowHttpLocal = true): string {
  let url: URL;
  try { url = new URL(u); } catch { throw new BadRequestException("Invalid URL: " + u); }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(allowHttpLocal && local && url.protocol === "http:"))
    throw new BadRequestException("URL must be https: " + u);
  if (url.pathname !== "/" || url.search || url.hash || url.username) throw new BadRequestException("Must be a bare origin: " + u);
  return url.origin;
}
@Injectable()
export class SettingsService {
  private cache?: { at: number; v: CentralSettings };
  constructor(@InjectModel("Setting") private model: Model<any>) {}
  async get(): Promise<CentralSettings> {
    if (this.cache && Date.now() - this.cache.at < 5000) return this.cache.v;
    const doc: any = await this.model.findOne({ key: "central" }).lean();
    const v = { ...EMPTY, ...(doc?.value || {}) };
    this.cache = { at: Date.now(), v };
    return v;
  }
  /** Cached synchronous view for CORS (refreshed by get()). */
  peek(): CentralSettings { void this.get().catch(() => {}); return this.cache?.v ?? EMPTY; }
  async issuer() {
    const s = await this.get();
    if (!s.publicUrl) throw new BadRequestException("Central publicUrl not set (network admin: Settings)");
    return s.publicUrl;
  }
  async view() {
    const { webhookSecret, ...rest } = await this.get();
    return { ...rest, webhookSecretSet: !!webhookSecret };
  }
  async update(patch: { publicUrl?: string; corsOrigins?: string[]; webhookSecret?: string | null }) {
    const set: any = {};
    if (patch.publicUrl !== undefined) set["value.publicUrl"] = origin(patch.publicUrl);
    if (patch.corsOrigins !== undefined) {
      if (!Array.isArray(patch.corsOrigins) || patch.corsOrigins.length > 20) throw new BadRequestException("corsOrigins: up to 20 origins");
      set["value.corsOrigins"] = [...new Set(patch.corsOrigins.map((o) => origin(o)))];
    }
    if (patch.webhookSecret === null) set["value.webhookSecret"] = "";
    else if (patch.webhookSecret !== undefined) {
      if (!/^whsec_[A-Za-z0-9+/=]{16,200}$/.test(patch.webhookSecret)) throw new BadRequestException("webhookSecret must look like whsec_...");
      set["value.webhookSecret"] = patch.webhookSecret;
    }
    await this.model.updateOne({ key: "central" }, { $set: set }, { upsert: true });
    this.cache = undefined;
    return this.view();
  }
}
