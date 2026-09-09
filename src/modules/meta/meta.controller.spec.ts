import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { MetaController } from './meta.controller';
import { CryptoService } from '../crypto/crypto.service';
import * as naclUtil from 'tweetnacl-util';

describe('MetaController', () => {
  let controller: MetaController;
  let cryptoService: CryptoService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [MetaController],
      providers: [
        CryptoService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              if (key === 'CENTRAL_KEY_FILE') return '/tmp/test_central_meta_key.json';
              return defaultValue;
            }),
          },
        },
      ],
    }).compile();

    controller = module.get<MetaController>(MetaController);
    cryptoService = module.get<CryptoService>(CryptoService);
    cryptoService.onModuleInit();
  });

  it('should return metadata signed with Central Server Ed25519 private key in x-central-signature header', () => {
    let headerKey = '';
    let headerValue = '';
    let sentBody = '';
    let statusCode = 0;

    const mockRes: any = {
      setHeader: jest.fn((k: string, v: string) => {
        if (k === 'x-central-signature') {
          headerKey = k;
          headerValue = v;
        }
      }),
      status: jest.fn((code: number) => {
        statusCode = code;
        return mockRes;
      }),
      send: jest.fn((body: string) => {
        sentBody = body;
        return mockRes;
      }),
    };

    controller.getCentralMetadata(mockRes);

    expect(statusCode).toBe(200);
    expect(headerKey).toBe('x-central-signature');
    expect(headerValue).toBeDefined();

    // Verify signature of the body using the public key in metadata
    const parsed = JSON.parse(sentBody);
    expect(parsed.service).toBe('carpschool-central');
    expect(parsed.version).toBe('2.0.0');
    expect(parsed.ed25519PublicKey).toBe(cryptoService.getPublicKeyBase64());

    const isValid = cryptoService.verifySchoolSignature(
      sentBody,
      headerValue,
      parsed.ed25519PublicKey,
    );
    expect(isValid).toBe(true);
  });
});
