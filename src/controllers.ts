import { Body, Controller, Get, Post, Patch, Param, Req, UseGuards, NotFoundException, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Webhook } from 'svix';
import { required } from './config';
import { ClerkGuard, AdminGuard } from './auth';
import { SigningService } from './security';
import { RegistryService } from './registry';
import { HeartbeatDto, OnboardDto, TicketDto, TrustDto } from './dto';
@ApiTags('central')
@Controller()
export class CentralController {
  constructor(private registry: RegistryService, private signing: SigningService) {}
  @Get('health') health() { return { ok: true }; }
  @Get('.well-known/jwks.json') jwks() { return this.signing.jwks(); }
  @Get('schools') async schools() { return this.registry.schools.find({ trusted: true }).select('_id schoolCode name domains baseUrl lastHeartbeat').lean(); }
  @Get('admin/schools') @ApiBearerAuth() @UseGuards(ClerkGuard, AdminGuard) adminSchools() { return this.registry.schools.find().lean(); }
  @Post('admin/schools') @ApiBearerAuth() @UseGuards(ClerkGuard, AdminGuard) onboard(@Body() dto: OnboardDto) { return this.registry.onboard(dto.baseUrl); }
  @Patch('admin/schools/:schoolCode/trust') @ApiBearerAuth() @UseGuards(ClerkGuard, AdminGuard) trust(@Param('schoolCode') code: string, @Body() dto: TrustDto) { return this.registry.trust(code, dto.trusted); }
  @Post('heartbeats') heartbeat(@Body() dto: HeartbeatDto) { return this.registry.heartbeat(dto); }
  @Post('tickets') @ApiBearerAuth() @UseGuards(ClerkGuard) async ticket(@Req() req: any, @Body() dto: TicketDto) {
    const school = await this.registry.schools.findOne({ schoolCode: dto.schoolCode, trusted: true });
    if (!school) throw new NotFoundException('Trusted school not found');
    const user = req.identity;
    const admin = user.privateMetadata?.school?.[school._id.toString()]?.admin === true;
    return this.signing.issue(user.id, school.schoolCode, admin, user.imageUrl || '', [user.firstName, user.lastName].filter(Boolean).join(' '));
  }
}
@ApiTags('webhooks')
@Controller('webhooks')
export class WebhookController {
  constructor(@InjectModel('User') private users: Model<any>, @InjectModel('Replay') private replay: Model<any>) {}
  @Post('clerk') async clerk(@Req() req: any) {
    let event: any;
    try { event = new Webhook(required('CLERK_WEBHOOK_SECRET')).verify(req.rawBody, { 'svix-id': req.headers['svix-id'], 'svix-timestamp': req.headers['svix-timestamp'], 'svix-signature': req.headers['svix-signature'] }); } catch { throw new UnauthorizedException('Invalid webhook signature'); }
    if (!['user.created', 'user.updated', 'user.deleted'].includes(event.type)) return { ok: true };
    if (typeof event.data?.id !== 'string' || typeof event.timestamp !== 'number') throw new BadRequestException('Malformed event');
    const key = 'webhook:' + req.headers['svix-id'];
    if (await this.replay.exists({ key })) return { ok: true };
    const data = event.data;
    // Conditional timestamp update prevents an older signed event overwriting a newer one.
    await this.users.updateOne({ clerkId: data.id }, { $setOnInsert: { clerkId: data.id, eventTimestamp: -1 } }, { upsert: true });
    await this.users.updateOne({ clerkId: data.id, eventTimestamp: { $lt: event.timestamp } }, { $set: { name: [data.first_name, data.last_name].filter(Boolean).join(' '), avatar: data.image_url || '', deleted: event.type === 'user.deleted', eventTimestamp: event.timestamp } });
    try { await this.replay.create({ key, expiresAt: new Date(Date.now() + 86400000) }); } catch (e) { if (e.code !== 11000) throw e; }
    return { ok: true };
  }
}
