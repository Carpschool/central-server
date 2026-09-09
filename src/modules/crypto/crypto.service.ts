import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';

/**
 * CryptoService
 * 
 * Manages the Central Authority's Ed25519 cryptographic keypair and performs
 * high-speed, non-repudiable cryptographic operations:
 * 
 * 1. Generating or loading Central Server's Ed25519 keypair.
 * 2. Signing outbound Federation Tickets for users connecting to school servers.
 * 3. Verifying incoming Ed25519 digital signatures from school servers during automated onboarding.
 */
@Injectable()
export class CryptoService implements OnModuleInit {
  private readonly logger = new Logger(CryptoService.name);
  private keyPair: nacl.SignKeyPair;

  constructor(private readonly configService: ConfigService) {}

  onModuleInit() {
    this.initializeKeys();
  }

  /**
   * Initializes the Ed25519 keypair from environment variables or generates
   * an ephemeral keypair for development if not provided.
   */
  private initializeKeys(): void {
    const privKeyBase64 = this.configService.get<string>('CENTRAL_ED25519_PRIVATE_KEY');
    const pubKeyBase64 = this.configService.get<string>('CENTRAL_ED25519_PUBLIC_KEY');

    if (privKeyBase64 && pubKeyBase64) {
      try {
        const secretKey = naclUtil.decodeBase64(privKeyBase64);
        const publicKey = naclUtil.decodeBase64(pubKeyBase64);
        this.keyPair = { publicKey, secretKey };
        this.logger.log(`🔐 Central Ed25519 Keypair loaded from environment. Public Key: ${pubKeyBase64}`);
        return;
      } catch (err) {
        this.logger.error(`Failed to decode base64 keys from environment: ${err.message}`);
      }
    }

    // Generate ephemeral keypair for development
    this.keyPair = nacl.sign.keyPair();
    const generatedPub = naclUtil.encodeBase64(this.keyPair.publicKey);
    const generatedPriv = naclUtil.encodeBase64(this.keyPair.secretKey);
    this.logger.warn(
      `⚠️  No valid Ed25519 keys found in environment. Generated ephemeral keypair for development.\n` +
      `   PUBLIC KEY:  ${generatedPub}\n` +
      `   PRIVATE KEY: ${generatedPriv}`
    );
  }

  /**
   * Returns the Central Server's public key in base64 format.
   */
  getPublicKeyBase64(): string {
    return naclUtil.encodeBase64(this.keyPair.publicKey);
  }

  /**
   * Signs an arbitrary string or JSON payload with Central Server's private key.
   * Returns a base64-encoded digital signature.
   */
  signMessage(message: string): string {
    const messageBytes = naclUtil.decodeUTF8(message);
    const signatureBytes = nacl.sign.detached(messageBytes, this.keyPair.secretKey);
    return naclUtil.encodeBase64(signatureBytes);
  }

  /**
   * Verifies an Ed25519 signature from a school server using the school's public key.
   * 
   * @param message The raw string message that was signed
   * @param signatureBase64 The base64 signature string
   * @param publicKeyBase64 The school's base64 public key
   * @returns boolean indicating whether the signature is cryptographically valid
   */
  verifySchoolSignature(
    message: string,
    signatureBase64: string,
    publicKeyBase64: string,
  ): boolean {
    try {
      const messageBytes = naclUtil.decodeUTF8(message);
      const signatureBytes = naclUtil.decodeBase64(signatureBase64);
      const publicKeyBytes = naclUtil.decodeBase64(publicKeyBase64);

      return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
    } catch (err) {
      this.logger.warn(`Signature verification error: ${err.message}`);
      return false;
    }
  }

  /**
   * Creates a cryptographically signed Federation Ticket for a client.
   * 
   * The ticket payload contains user claims, target school identifier, trust flag,
   * issue timestamp, and expiration timestamp.
   */
  createSignedFederationTicket(payload: {
    centralUserId: string;
    clerkUserId: string;
    fullName: string;
    primaryEmail: string;
    schoolCode: string;
    isTrusted: boolean;
    expiresInSeconds?: number;
  }): { ticket: string; expiresAt: Date; signature: string } {
    const now = new Date();
    const expiresIn = payload.expiresInSeconds || 86400; // Default 24 hours
    const expiresAt = new Date(now.getTime() + expiresIn * 1000);

    const ticketData = {
      centralUserId: payload.centralUserId,
      clerkUserId: payload.clerkUserId,
      fullName: payload.fullName,
      primaryEmail: payload.primaryEmail,
      schoolCode: payload.schoolCode,
      isTrusted: payload.isTrusted,
      issuedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      issuer: 'carpschool-central',
    };

    const canonicalString = JSON.stringify(ticketData);
    const signature = this.signMessage(canonicalString);

    // Combine canonical payload and signature in a single base64 ticket token
    const tokenPackage = {
      data: ticketData,
      signature: signature,
      centralPublicKey: this.getPublicKeyBase64(),
    };

    const ticket = Buffer.from(JSON.stringify(tokenPackage)).toString('base64');

    return {
      ticket,
      expiresAt,
      signature,
    };
  }
}
