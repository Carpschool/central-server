import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SchoolsService } from './schools.service';
import { CryptoService } from '../crypto/crypto.service';
import { School } from './schemas/school.schema';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';

describe('SchoolsService', () => {
  let service: SchoolsService;
  let cryptoService: CryptoService;

  const mockSchoolDoc = {
    _id: 'school_123',
    schoolCode: 'ubc',
    officialName: 'University of British Columbia',
    allowedEmailDomains: ['ubc.ca'],
    baseUrl: 'https://ubc.carpschool.ca',
    ed25519PublicKey: 'mock_public_key_base64',
    isTrusted: true,
    lastHeartbeat: new Date(),
    save: jest.fn().mockResolvedValue(true),
  };

  const mockSchoolModel = {
    findOneAndUpdate: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SchoolsService,
        CryptoService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              if (key === 'CENTRAL_KEY_FILE') return '/tmp/test_central_schools_key.json';
              return defaultValue;
            }),
          },
        },
        {
          provide: getModelToken(School.name),
          useValue: mockSchoolModel,
        },
      ],
    }).compile();

    service = module.get<SchoolsService>(SchoolsService);
    cryptoService = module.get<CryptoService>(CryptoService);
    cryptoService.onModuleInit();
  });

  describe('issueFederationTicket', () => {
    it('should issue a trusted ticket for a registered school', async () => {
      mockSchoolModel.findOne.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mockSchoolDoc),
      });

      const user = { userId: 'clerk_user_1', email: 'alice@ubc.ca', fullName: 'Alice' };
      const result = await service.issueFederationTicket(user, { schoolCode: 'ubc' });

      expect(result.isTrusted).toBe(true);
      expect(result.schoolBaseUrl).toBe('https://ubc.carpschool.ca');
      expect(result.ticket).toBeDefined();

      const decoded = JSON.parse(Buffer.from(result.ticket, 'base64').toString('utf8'));
      expect(decoded.data.clerkUserId).toBe('clerk_user_1');
      expect(decoded.data.isTrusted).toBe(true);
      expect(decoded.data.schoolCode).toBe('ubc');
    });

    it('should issue an untrusted ticket for an unlisted custom school URL', async () => {
      const user = { userId: 'clerk_user_2', email: 'bob@custom.org', fullName: 'Bob' };
      const result = await service.issueFederationTicket(user, {
        schoolCode: 'custom',
        customBaseUrl: 'https://community-school.org:8443',
      });

      expect(result.isTrusted).toBe(false);
      expect(result.schoolBaseUrl).toBe('https://community-school.org:8443');

      const decoded = JSON.parse(Buffer.from(result.ticket, 'base64').toString('utf8'));
      expect(decoded.data.isTrusted).toBe(false);
      expect(decoded.data.schoolCode).toBe('custom');
    });

    it('should throw BadRequestException if custom URL is missing for unlisted school', async () => {
      const user = { userId: 'clerk_user_3' };
      await expect(
        service.issueFederationTicket(user, { schoolCode: 'custom' }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('onboardSchool', () => {
    it('should onboard a school successfully when signature matches metadata', async () => {
      // Generate a test school keypair
      const schoolKeyPair = nacl.sign.keyPair();
      const schoolPubKey = naclUtil.encodeBase64(schoolKeyPair.publicKey);

      const metadataPayload = {
        schoolCode: 'ubc',
        officialName: 'University of British Columbia',
        allowedEmailDomains: ['ubc.ca'],
        campusLocation: { latitude: 49.2606, longitude: -123.246 },
      };

      const rawBody = JSON.stringify(metadataPayload);
      const signatureBytes = nacl.sign.detached(
        naclUtil.decodeUTF8(rawBody),
        schoolKeyPair.secretKey,
      );
      const signatureBase64 = naclUtil.encodeBase64(signatureBytes);

      // Mock global fetch to return the signed metadata
      const mockFetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => rawBody,
        headers: {
          get: (name: string) => (name.toLowerCase() === 'x-school-signature' ? signatureBase64 : null),
        },
      });
      globalThis.fetch = mockFetch as any;

      mockSchoolModel.findOneAndUpdate.mockResolvedValue({
        ...mockSchoolDoc,
        ed25519PublicKey: schoolPubKey,
      });

      const result = await service.onboardSchool({
        baseUrl: 'https://ubc.carpschool.ca',
        ed25519PublicKey: schoolPubKey,
      });

      expect(result).toBeDefined();
      expect(mockSchoolModel.findOneAndUpdate).toHaveBeenCalledWith(
        { schoolCode: 'ubc' },
        expect.objectContaining({
          schoolCode: 'ubc',
          officialName: 'University of British Columbia',
          isTrusted: true,
          ed25519PublicKey: schoolPubKey,
        }),
        { upsert: true, new: true },
      );
    });

    it('should reject onboarding if signature does not match public key', async () => {
      const schoolKeyPair = nacl.sign.keyPair();
      const schoolPubKey = naclUtil.encodeBase64(schoolKeyPair.publicKey);

      // Different key signs the message
      const attackerKeyPair = nacl.sign.keyPair();
      const rawBody = JSON.stringify({ schoolCode: 'ubc', officialName: 'UBC' });
      const badSig = naclUtil.encodeBase64(
        nacl.sign.detached(naclUtil.decodeUTF8(rawBody), attackerKeyPair.secretKey),
      );

      globalThis.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => rawBody,
        headers: {
          get: (name: string) => (name.toLowerCase() === 'x-school-signature' ? badSig : null),
        },
      }) as any;

      await expect(
        service.onboardSchool({
          baseUrl: 'https://ubc.carpschool.ca',
          ed25519PublicKey: schoolPubKey,
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('recordHeartbeat', () => {
    it('should verify heartbeat and update lastHeartbeat', async () => {
      const schoolKeyPair = nacl.sign.keyPair();
      const schoolPubKey = naclUtil.encodeBase64(schoolKeyPair.publicKey);

      const heartbeatDto = {
        schoolCode: 'ubc',
        timestamp: new Date().toISOString(),
        activeCarpools: 5,
        activeStudents: 20,
      };

      const rawPayload = JSON.stringify(heartbeatDto);
      const signature = naclUtil.encodeBase64(
        nacl.sign.detached(naclUtil.decodeUTF8(rawPayload), schoolKeyPair.secretKey),
      );

      const registeredSchool = {
        ...mockSchoolDoc,
        ed25519PublicKey: schoolPubKey,
        save: jest.fn().mockResolvedValue(true),
      };

      mockSchoolModel.findOne.mockReturnValue({
        exec: jest.fn().mockResolvedValue(registeredSchool),
      });

      const response = await service.recordHeartbeat(heartbeatDto, signature, rawPayload);
      expect(response.status).toBe('ok');
      expect(registeredSchool.save).toHaveBeenCalled();
    });

    it('should reject heartbeat with forged signature', async () => {
      const schoolKeyPair = nacl.sign.keyPair();
      const schoolPubKey = naclUtil.encodeBase64(schoolKeyPair.publicKey);

      const heartbeatDto = {
        schoolCode: 'ubc',
        timestamp: new Date().toISOString(),
      };

      const registeredSchool = {
        ...mockSchoolDoc,
        ed25519PublicKey: schoolPubKey,
      };

      mockSchoolModel.findOne.mockReturnValue({
        exec: jest.fn().mockResolvedValue(registeredSchool),
      });

      await expect(
        service.recordHeartbeat(heartbeatDto, 'invalid_base64_sig', JSON.stringify(heartbeatDto)),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
