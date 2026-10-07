import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { randomBytes } from "node:crypto";
import { HeartbeatDto } from "./dto";
import { publicJson, schoolKey, validSignature } from "./security";
@Injectable()
export class RegistryService {
  constructor(
    @InjectModel("School") public schools: Model<any>,
    @InjectModel("Replay") private replay: Model<any>,
  ) {}
  /** Fetch + validate school metadata and prove key possession via signed challenge. */
  async verifyOrigin(baseUrl: string) {
    const origin = new URL(baseUrl);
    if (origin.pathname !== "/" || origin.search || origin.hash)
      throw new BadRequestException("School baseUrl must be an origin");
    const meta = await publicJson(
      new URL("/.well-known/carpschool.json", origin),
    );
    if (
      typeof meta.schoolCode !== "string" ||
      !/^[a-zA-Z0-9_-]{2,64}$/.test(meta.schoolCode) ||
      typeof meta.name !== "string" ||
      !meta.name.trim() ||
      meta.name.length > 200 ||
      !Array.isArray(meta.domains) ||
      !meta.domains.length ||
      meta.domains.length > 30 ||
      meta.domains.some(
        (d: any) =>
          typeof d !== "string" ||
          !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?[.])+[a-z]{2,63}$/.test(d),
      ) ||
      typeof meta.publicKey !== "string" ||
      meta.publicKey.length > 2048 ||
      meta.baseUrl !== origin.origin
    )
      throw new BadRequestException("Invalid school metadata");
    try {
      schoolKey(meta.publicKey);
    } catch {
      throw new BadRequestException("Invalid Ed25519 key");
    }
    const nonce = randomBytes(32).toString("base64url");
    const challenge = await publicJson(
      new URL("/federation/challenge?nonce=" + nonce, origin),
    );
    if (!validSignature(meta.publicKey, nonce, challenge.signature))
      throw new UnauthorizedException("Challenge signature rejected");
    return { meta, origin };
  }
  async onboard(baseUrl: string) {
    const { meta, origin } = await this.verifyOrigin(baseUrl);
    try {
      return await this.schools.create({
        schoolCode: meta.schoolCode,
        name: meta.name,
        domains: meta.domains,
        publicKey: meta.publicKey,
        baseUrl: origin.origin,
        trusted: true,
      });
    } catch (e) {
      if (e.code === 11000)
        throw new ConflictException("School already registered");
      throw e;
    }
  }
  async update(
    code: string,
    patch: { name?: string; domains?: string[]; baseUrl?: string },
  ) {
    const school = await this.schools.findOne({ schoolCode: code });
    if (!school) throw new NotFoundException();
    const set: any = {};
    if (patch.name !== undefined) set.name = patch.name.trim();
    if (patch.domains !== undefined)
      set.domains = [...new Set(patch.domains.map((d) => d.toLowerCase()))];
    if (patch.baseUrl !== undefined) {
      const { meta, origin } = await this.verifyOrigin(patch.baseUrl);
      if (meta.schoolCode !== school.schoolCode || meta.publicKey !== school.publicKey)
        throw new BadRequestException(
          "New baseUrl must serve the same school code and signing key",
        );
      set.baseUrl = origin.origin;
    }
    return this.schools.findOneAndUpdate({ schoolCode: code }, set, { new: true });
  }
  async trust(code: string, trusted: boolean) {
    const school = await this.schools.findOneAndUpdate(
      { schoolCode: code },
      { trusted },
      { new: true },
    );
    if (!school) throw new NotFoundException();
    return school;
  }
  async heartbeat(dto: HeartbeatDto) {
    if (Math.abs(Date.now() - dto.timestamp) > 60000)
      throw new UnauthorizedException(
        "Stale heartbeat (timestamp is milliseconds)",
      );
    const school = await this.schools.findOne({
      schoolCode: dto.schoolCode,
      trusted: true,
    });
    if (
      !school ||
      !validSignature(
        school.publicKey,
        JSON.stringify({
          schoolCode: dto.schoolCode,
          timestamp: dto.timestamp,
          nonce: dto.nonce,
        }),
        dto.signature,
      )
    )
      throw new UnauthorizedException("Invalid heartbeat");
    try {
      await this.replay.create({
        key: dto.schoolCode + ":" + dto.nonce,
        expiresAt: new Date(Date.now() + 120000),
      });
    } catch (e) {
      if (e.code === 11000) throw new ConflictException("Replayed heartbeat");
      throw e;
    }
    await this.schools.updateOne(
      { _id: school._id, trusted: true },
      { lastHeartbeat: new Date() },
    );
    return { ok: true };
  }
}
