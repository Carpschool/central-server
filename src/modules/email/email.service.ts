import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

/**
 * EmailService
 * 
 * Handles dispatch of security and verification emails from security@carpschool.ca.
 * Supports:
 *  1. Gmail OAuth2 (type: 'OAuth2')
 *  2. Gmail App Password (service: 'gmail')
 *  3. Standard SMTP relay
 *  4. Development Mock mode
 */
@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter | null = null;

  constructor(private readonly configService: ConfigService) {
    this.initializeTransporter();
  }

  private initializeTransporter(): void {
    const gmailUser = this.configService.get<string>('GMAIL_USER');
    const gmailAppPassword = this.configService.get<string>('GMAIL_APP_PASSWORD');
    const oauthClientId = this.configService.get<string>('GMAIL_OAUTH_CLIENT_ID');
    const oauthClientSecret = this.configService.get<string>('GMAIL_OAUTH_CLIENT_SECRET');
    const oauthRefreshToken = this.configService.get<string>('GMAIL_OAUTH_REFRESH_TOKEN');

    // 1. Gmail OAuth2
    if (gmailUser && oauthClientId && oauthClientSecret && oauthRefreshToken) {
      this.logger.log(`📧 Configuring Central Gmail OAuth2 transport for ${gmailUser}`);
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          type: 'OAuth2',
          user: gmailUser,
          clientId: oauthClientId,
          clientSecret: oauthClientSecret,
          refreshToken: oauthRefreshToken,
        },
      });
      return;
    }

    // 2. Gmail App Password
    if (gmailUser && gmailAppPassword) {
      this.logger.log(`📧 Configuring Central Gmail App Password SMTP transport for ${gmailUser}`);
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: gmailUser,
          pass: gmailAppPassword.replace(/\s+/g, ''),
        },
      });
      return;
    }

    // 3. Generic SMTP
    const smtpHost = this.configService.get<string>('SMTP_HOST');
    const smtpUser = this.configService.get<string>('SMTP_USER');
    const smtpPass = this.configService.get<string>('SMTP_PASS');
    if (smtpHost && smtpUser && smtpPass) {
      const smtpPort = parseInt(this.configService.get<string>('SMTP_PORT', '587'), 10);
      this.logger.log(`📧 Configuring Central SMTP transport (${smtpHost}:${smtpPort}) for ${smtpUser}`);
      this.transporter = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: {
          user: smtpUser,
          pass: smtpPass,
        },
      });
      return;
    }

    // 4. Fallback: Development Mock
    this.logger.log('📧 Using Central Mock Email provider.');
    this.transporter = null;
  }

  /**
   * Sends a 6-digit account verification code from security@carpschool.ca
   */
  async sendAccountVerificationCode(toEmail: string, code: string): Promise<boolean> {
    const sender =
      this.configService.get<string>('GMAIL_USER') ||
      this.configService.get<string>('SMTP_USER') ||
      'security@carpschool.ca';

    if (!this.transporter) {
      this.logger.log(`[MOCK EMAIL] From: ${sender} | To: ${toEmail} | Code: ${code}`);
      return true;
    }

    try {
      await this.transporter.sendMail({
        from: `"Carpschool Security" <${sender}>`,
        to: toEmail,
        subject: `Your Carpschool Security Code: ${code}`,
        text: `Your Carpschool security verification code is: ${code}\n\nValid for 15 minutes.`,
      });
      return true;
    } catch (err: any) {
      this.logger.error(`❌ Central mail delivery failed: ${err.message}`);
      return false;
    }
  }
}
