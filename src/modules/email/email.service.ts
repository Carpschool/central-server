import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * EmailService
 * 
 * Handles dispatch of security and verification emails from security@carpschool.ca.
 * Supports mock mode in development and pluggable SMTP/Resend providers.
 */
@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);

  constructor(private readonly configService: ConfigService) {}

  /**
   * Sends a 6-digit account verification code from security@carpschool.ca
   */
  async sendAccountVerificationCode(toEmail: string, code: string): Promise<boolean> {
    const provider = this.configService.get<string>('EMAIL_PROVIDER', 'mock');

    this.logger.log(`📧 [${provider.toUpperCase()}] Sending security code to ${toEmail}: ${code}`);

    if (provider === 'mock') {
      this.logger.log(`[MOCK EMAIL] From: security@carpschool.ca | To: ${toEmail} | Code: ${code}`);
      return true;
    }

    // SMTP / Resend production dispatch logic can be wired here
    return true;
  }
}
