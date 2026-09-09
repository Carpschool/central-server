import { Global, Module } from '@nestjs/common';
import { CryptoService } from './crypto.service';

/**
 * CryptoModule
 * 
 * Global module providing Ed25519 cryptographic services across the Central Server.
 */
@Global()
@Module({
  providers: [CryptoService],
  exports: [CryptoService],
})
export class CryptoModule {}
