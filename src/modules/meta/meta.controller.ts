import { Controller, Get, Res, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Response } from 'express';
import { CryptoService } from '../crypto/crypto.service';

/**
 * MetaController
 * 
 * Exposes Central Authority Server public identity and Ed25519 public key.
 * Every response is cryptographically signed with Central Server's private key
 * in the 'x-central-signature' HTTP response header.
 */
@ApiTags('metadata')
@Controller('api/v1/meta')
export class MetaController {
  constructor(private readonly cryptoService: CryptoService) {}

  @Get()
  @ApiOperation({
    summary: 'Public Central Authority Metadata & Ed25519 Public Key',
    description:
      'Returns Central Server metadata and public key. The payload is digitally signed with Central Server Ed25519 private key in the x-central-signature header.',
  })
  @ApiResponse({ status: 200, description: 'Central Server signed metadata' })
  getCentralMetadata(@Res() res: Response) {
    const payload = {
      service: 'carpschool-central',
      version: '2.0.0',
      ed25519PublicKey: this.cryptoService.getPublicKeyBase64(),
      timestamp: new Date().toISOString(),
    };

    const payloadString = JSON.stringify(payload);
    const signature = this.cryptoService.signMessage(payloadString);

    // Attach Central Server's Ed25519 signature in HTTP response header
    res.setHeader('x-central-signature', signature);
    res.setHeader('Content-Type', 'application/json');

    return res.status(HttpStatus.OK).send(payloadString);
  }
}
