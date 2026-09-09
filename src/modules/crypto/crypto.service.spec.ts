import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { CryptoService } from './crypto.service';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';

describe('CryptoService', () => {
  let service: CryptoService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CryptoService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              if (key === 'CENTRAL_KEY_FILE') return '/tmp/test_central_key.json';
              return defaultValue;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<CryptoService>(CryptoService);
    service.onModuleInit();
  });

  it('should initialize and provide a valid Ed25519 base64 public key', () => {
    const pubKey = service.getPublicKeyBase64();
    expect(pubKey).toBeDefined();
    expect(typeof pubKey).toBe('string');
    // Ed25519 public key is 32 bytes -> 44 chars in base64
    const decoded = naclUtil.decodeBase64(pubKey);
    expect(decoded.length).toBe(32);
  });

  it('should sign messages and verify signatures using Central Server public key', () => {
    const message = 'test-carpschool-payload-12345';
    const signature = service.signMessage(message);

    expect(signature).toBeDefined();
    const sigBytes = naclUtil.decodeBase64(signature);
    expect(sigBytes.length).toBe(64); // Ed25519 signature is 64 bytes

    // Verify using verifySchoolSignature with Central's own public key
    const isValid = service.verifySchoolSignature(
      message,
      signature,
      service.getPublicKeyBase64(),
    );
    expect(isValid).toBe(true);
  });

  it('should reject invalid or tampered signatures', () => {
    const originalMessage = '{"schoolCode":"ubc","role":"rider"}';
    const tamperedMessage = '{"schoolCode":"ubc","role":"admin"}';
    const signature = service.signMessage(originalMessage);

    const isValid = service.verifySchoolSignature(
      tamperedMessage,
      signature,
      service.getPublicKeyBase64(),
    );
    expect(isValid).toBe(false);
  });

  it('should create a valid Federation Ticket package', () => {
    const ticketResult = service.createSignedFederationTicket({
      centralUserId: 'user_123',
      clerkUserId: 'clerk_456',
      fullName: 'Alice Student',
      primaryEmail: 'alice@ubc.ca',
      schoolCode: 'ubc',
      isTrusted: true,
      expiresInSeconds: 3600,
    });

    expect(ticketResult.ticket).toBeDefined();
    expect(ticketResult.signature).toBeDefined();
    expect(ticketResult.expiresAt).toBeInstanceOf(Date);

    // Decode ticket base64
    const decodedJson = Buffer.from(ticketResult.ticket, 'base64').toString('utf8');
    const tokenPackage = JSON.parse(decodedJson);

    expect(tokenPackage.data.centralUserId).toBe('user_123');
    expect(tokenPackage.data.schoolCode).toBe('ubc');
    expect(tokenPackage.data.isTrusted).toBe(true);
    expect(tokenPackage.centralPublicKey).toBe(service.getPublicKeyBase64());

    // Verify signature of the canonical payload
    const canonicalString = JSON.stringify(tokenPackage.data);
    const isValid = service.verifySchoolSignature(
      canonicalString,
      tokenPackage.signature,
      tokenPackage.centralPublicKey,
    );
    expect(isValid).toBe(true);
  });
});
