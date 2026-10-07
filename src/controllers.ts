import {
  Body,
  Controller,
  Get,
  Post,
  Patch,
  Put,
  Query,
  Param,
  Req,
  UseGuards,
  NotFoundException,
  UnauthorizedException,
  BadRequestException,
} from "@nestjs/common";
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger";
import { Throttle } from "@nestjs/throttler";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { Webhook } from "svix";
import { SettingsService } from "./settings";
import { ClerkGuard, AdminGuard } from "./auth";
import { SigningService } from "./security";
import { RegistryService } from "./registry";
import { HeartbeatDto, OnboardDto, TicketDto, EnabledDto, AdminFlagDto, ClaimDto, CentralSettingsDto } from "./dto";
import { AdminsService } from "./admins";
@ApiTags("central")
@Controller()
export class CentralController {
  constructor(
    private registry: RegistryService,
    private signing: SigningService,
    private admins: AdminsService,
    private settings: SettingsService,
    @InjectModel("User") private userDocs: Model<any>,
  ) {}
  @Get("admin/settings")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  getSettings() {
    return this.settings.view();
  }
  @Put("admin/settings")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  putSettings(@Body() dto: CentralSettingsDto) {
    return this.settings.update(dto);
  }
  @Post("admin/schools/claim")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  @Throttle({ default: { ttl: 600000, limit: 10 } })
  claim(@Body() dto: ClaimDto) {
    return this.registry.claim(dto.baseUrl, dto.code, dto.schoolCode, dto.name);
  }
  @Get("health") health() {
    return { ok: true };
  }
  @Get(".well-known/jwks.json") jwks() {
    return this.signing.jwks();
  }
  @Get("schools") async schools() {
    return this.registry.schools
      .find({ trusted: true, enabled: { $ne: false } })
      .select("_id schoolCode name domains baseUrl lastHeartbeat")
      .lean();
  }
  @Get("admin/schools")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  adminSchools() {
    return this.registry.schools.find().lean();
  }
  @Post("admin/schools")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  onboard(@Body() dto: OnboardDto) {
    return this.registry.onboard(dto.baseUrl);
  }
  @Patch("admin/schools/:schoolCode/enabled")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  async setEnabled(@Param("schoolCode") code: string, @Body() dto: EnabledDto) {
    const s = await this.registry.schools.findOneAndUpdate({ schoolCode: code }, { enabled: dto.enabled }, { new: true }).lean();
    if (!s) throw new NotFoundException("School not found");
    return s;
  }
  // School settings belong to school admins; network admins only see who uses a school and who administers it.
  @Get("admin/schools/:schoolCode/users")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  async schoolUsers(@Param("schoolCode") code: string) {
    const s: any = await this.registry.schools.findOne({ schoolCode: code }).lean();
    if (!s) throw new NotFoundException("School not found");
    const ids = (await this.userDocs.find({ schools: String(s._id) }).select("clerkId").limit(500).lean()).map((u: any) => u.clerkId);
    if (!ids.length) return [];
    return (await this.admins.byIds(ids)).map((u) => ({ ...u, schoolAdmin: u.school?.[String(s._id)]?.admin === true }));
  }
  @Get("admin/users/:id")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  async user(@Param("id") id: string) {
    const profile = await this.admins.one(id);
    const doc: any = await this.userDocs.findOne({ clerkId: id }).lean();
    const ids = [...new Set([...(doc?.schools ?? []), ...Object.keys(profile.school)])].filter((x) => /^[a-f0-9]{24}$/i.test(x));
    const schools = await this.registry.schools.find({ _id: { $in: ids } }).select("_id schoolCode name baseUrl enabled").lean();
    return {
      ...profile,
      firstSeen: doc?.createdAt ?? null,
      lastSeen: doc?.updatedAt ?? null,
      schools: schools.map((s: any) => ({ ...s, used: (doc?.schools ?? []).includes(String(s._id)), schoolAdmin: profile.school[String(s._id)]?.admin === true })),
    };
  }
  @Get("admin/users")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  users(@Query("q") q?: string) {
    return this.admins.list(typeof q === "string" ? q : undefined);
  }
  @Put("admin/users/:id/schools/:schoolId/admin")
  @ApiBearerAuth()
  @UseGuards(ClerkGuard, AdminGuard)
  async setSchoolAdmin(@Param("id") id: string, @Param("schoolId") schoolId: string, @Body() dto: AdminFlagDto) {
    if (!/^[a-f0-9]{24}$/i.test(schoolId) || !(await this.registry.schools.exists({ _id: schoolId })))
      throw new NotFoundException("School not found");
    return this.admins.setSchool(id, schoolId, dto.admin);
  }
  @Post("heartbeats") heartbeat(@Body() dto: HeartbeatDto) {
    return this.registry.heartbeat(dto);
  }
  @Post("tickets") @ApiBearerAuth() @UseGuards(ClerkGuard) async ticket(
    @Req() req: any,
    @Body() dto: TicketDto,
  ) {
    const school = await this.registry.schools.findOne({
      schoolCode: dto.schoolCode,
      trusted: true,
      enabled: { $ne: false },
    });
    if (!school) throw new NotFoundException("School not found or disabled");
    const user = req.identity;
    await this.userDocs.updateOne(
      { clerkId: user.id },
      { $addToSet: { schools: school._id.toString() }, $set: { name: [user.firstName, user.lastName].filter(Boolean).join(" "), avatar: user.imageUrl || "" } },
      { upsert: true },
    );
    const admin =
      user.privateMetadata?.school?.[school._id.toString()]?.admin === true;
    return this.signing.issue(
      user.id,
      school.schoolCode,
      admin,
      user.imageUrl || "",
      [user.firstName, user.lastName].filter(Boolean).join(" "),
    );
  }
}
@ApiTags("webhooks")
@Controller("webhooks")
export class WebhookController {
  constructor(
    @InjectModel("User") private users: Model<any>,
    @InjectModel("Replay") private replay: Model<any>,
    private settings: SettingsService,
  ) {}
  @Post("clerk") async clerk(@Req() req: any) {
    let event: any;
    try {
      const secret = (await this.settings.get()).webhookSecret;
      if (!secret) throw new Error("no webhook secret");
      event = new Webhook(secret).verify(
        req.rawBody,
        {
          "svix-id": req.headers["svix-id"],
          "svix-timestamp": req.headers["svix-timestamp"],
          "svix-signature": req.headers["svix-signature"],
        },
      );
    } catch {
      throw new UnauthorizedException("Invalid webhook signature");
    }
    if (!["user.created", "user.updated", "user.deleted"].includes(event.type))
      return { ok: true };
    if (
      typeof event.data?.id !== "string" ||
      typeof event.timestamp !== "number"
    )
      throw new BadRequestException("Malformed event");
    const key = "webhook:" + req.headers["svix-id"];
    if (await this.replay.exists({ key })) return { ok: true };
    const data = event.data;
    // Conditional timestamp update prevents an older signed event overwriting a newer one.
    await this.users.updateOne(
      { clerkId: data.id },
      { $setOnInsert: { clerkId: data.id, eventTimestamp: -1 } },
      { upsert: true },
    );
    await this.users.updateOne(
      { clerkId: data.id, eventTimestamp: { $lt: event.timestamp } },
      {
        $set: {
          name: [data.first_name, data.last_name].filter(Boolean).join(" "),
          avatar: data.image_url || "",
          deleted: event.type === "user.deleted",
          eventTimestamp: event.timestamp,
        },
      },
    );
    try {
      await this.replay.create({
        key,
        expiresAt: new Date(Date.now() + 86400000),
      });
    } catch (e) {
      if (e.code !== 11000) throw e;
    }
    return { ok: true };
  }
}
