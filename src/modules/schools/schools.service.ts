import {
  Injectable,
  BadRequestException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { School, SchoolDocument } from './schemas/school.schema';
import { OnboardSchoolDto } from './dto/onboard-school.dto';
import { SchoolHeartbeatDto } from './dto/school-heartbeat.dto';
import { CreateTicketDto } from './dto/create-ticket.dto';
import { CryptoService } from '../crypto/crypto.service';

@Injectable()
export class SchoolsService {
  private readonly logger = new Logger(SchoolsService.name);

  constructor(
    @InjectModel(School.name) private readonly schoolModel: Model<SchoolDocument>,
    private readonly cryptoService: CryptoService,
  ) {}

  /**
   * Automated Admin School Onboarding
   * 
   * Fetches metadata from the school server's /api/v1/meta endpoint, verifies the
   * returned Ed25519 digital signature against the admin-supplied public key,
   * and automatically populates the school profile in MongoDB.
   */
  async onboardSchool(dto: OnboardSchoolDto): Promise<School> {
    const cleanBaseUrl = dto.baseUrl.replace(/\/+$/, '');
    const metaUrl = `${cleanBaseUrl}/api/v1/meta`;

    this.logger.log(`Fetching metadata from school server: ${metaUrl}`);

    let response: globalThis.Response;
    try {
      response = await fetch(metaUrl, {
        method: 'GET',
        headers: { Accept: 'application/json' },
      });
    } catch (err) {
      throw new BadRequestException(
        `Failed to connect to school server at ${metaUrl}: ${err.message}`,
      );
    }

    if (!response.ok) {
      throw new BadRequestException(
        `School server returned HTTP status ${response.status} from ${metaUrl}`,
      );
    }

    const rawBody = await response.text();
    const signature = response.headers.get('x-school-signature');

    if (!signature) {
      throw new BadRequestException(
        'School server did not provide the required x-school-signature HTTP response header',
      );
    }

    // Cryptographic validation of the School Server's Ed25519 signature
    const isValidSignature = this.cryptoService.verifySchoolSignature(
      rawBody,
      signature,
      dto.ed25519PublicKey,
    );

    if (!isValidSignature) {
      throw new BadRequestException(
        'Cryptographic signature verification failed! The response was not signed by the provided Ed25519 public key.',
      );
    }

    let metaData: any;
    try {
      metaData = JSON.parse(rawBody);
    } catch (err) {
      throw new BadRequestException('School server returned malformed JSON');
    }

    if (!metaData.schoolCode || !metaData.officialName) {
      throw new BadRequestException(
        'School metadata missing required fields: schoolCode, officialName',
      );
    }

    // Auto-populate and upsert school in central_db
    const school = await this.schoolModel.findOneAndUpdate(
      { schoolCode: metaData.schoolCode.toLowerCase() },
      {
        schoolCode: metaData.schoolCode.toLowerCase(),
        officialName: metaData.officialName,
        allowedEmailDomains: metaData.allowedEmailDomains || [],
        baseUrl: cleanBaseUrl,
        ed25519PublicKey: dto.ed25519PublicKey,
        isTrusted: true,
        campusLocation: metaData.campusLocation || null,
        logoUrl: metaData.logoUrl || null,
        lastHeartbeat: new Date(),
      },
      { upsert: true, new: true },
    );

    this.logger.log(
      `✅ School "${school.officialName}" (${school.schoolCode}) onboarded and verified successfully!`,
    );

    return school;
  }

  /**
   * Retrieves the directory of all admin-verified trusted schools.
   */
  async listTrustedSchools(): Promise<School[]> {
    return this.schoolModel.find({ isTrusted: true }).sort({ officialName: 1 }).exec();
  }

  /**
   * Finds a specific school by its code.
   */
  async getSchoolByCode(schoolCode: string): Promise<School> {
    const school = await this.schoolModel
      .findOne({ schoolCode: schoolCode.toLowerCase() })
      .exec();

    if (!school) {
      throw new NotFoundException(`School with code "${schoolCode}" not found`);
    }

    return school;
  }

  /**
   * Generates an Ed25519-signed Federation Ticket for a user to connect to a school server.
   * Supports both trusted registered schools and untrusted custom Base URLs.
   */
  async issueFederationTicket(
    user: { userId: string; email?: string; fullName?: string },
    dto: CreateTicketDto,
  ): Promise<{
    ticket: string;
    schoolBaseUrl: string;
    isTrusted: boolean;
    expiresAt: Date;
  }> {
    let targetBaseUrl = '';
    let isTrusted = false;
    let schoolCode = dto.schoolCode.toLowerCase();

    if (schoolCode === 'custom' || dto.customBaseUrl) {
      if (!dto.customBaseUrl) {
        throw new BadRequestException(
          'customBaseUrl is required when requesting a ticket for an unlisted server',
        );
      }
      targetBaseUrl = dto.customBaseUrl.replace(/\/+$/, '');
      schoolCode = 'custom';
      isTrusted = false;
    } else {
      const school = await this.getSchoolByCode(schoolCode);
      targetBaseUrl = school.baseUrl;
      isTrusted = school.isTrusted;
    }

    const ticketPackage = this.cryptoService.createSignedFederationTicket({
      centralUserId: user.userId,
      clerkUserId: user.userId,
      fullName: user.fullName || 'Student',
      primaryEmail: user.email || '',
      schoolCode,
      isTrusted,
      expiresInSeconds: 86400, // 24 hours
    });

    return {
      ticket: ticketPackage.ticket,
      schoolBaseUrl: targetBaseUrl,
      isTrusted,
      expiresAt: ticketPackage.expiresAt,
    };
  }

  /**
   * Processes a school heartbeat:
   * 1. Finds the school in MongoDB
   * 2. Verifies the Ed25519 digital signature against registered public key
   * 3. Updates lastHeartbeat timestamp
   */
  async recordHeartbeat(
    dto: SchoolHeartbeatDto,
    signature: string,
    rawBody?: string,
  ): Promise<{ status: string; acknowledgedAt: string }> {
    const school = await this.schoolModel
      .findOne({ schoolCode: dto.schoolCode.toLowerCase() })
      .exec();

    if (!school) {
      throw new NotFoundException(`School with code "${dto.schoolCode}" not found`);
    }

    if (!signature) {
      throw new BadRequestException('Missing x-school-signature header');
    }

    // Verify signature using raw body if available, or canonical stringified DTO
    const messageToVerify = rawBody || JSON.stringify(dto);
    const isValid = this.cryptoService.verifySchoolSignature(
      messageToVerify,
      signature,
      school.ed25519PublicKey,
    );

    if (!isValid) {
      throw new BadRequestException('Cryptographic heartbeat signature verification failed');
    }

    // Update school's heartbeat timestamp in central_db
    school.lastHeartbeat = new Date();
    await school.save();

    this.logger.log(`💓 Verified heartbeat from school: ${school.officialName} (${school.schoolCode})`);

    return {
      status: 'ok',
      acknowledgedAt: new Date().toISOString(),
    };
  }
}
