import { Injectable, Logger } from '@nestjs/common';

/**
 * EmailService
 * 
 * Policy: Central Server sends 0 emails.
 * Account management and identity authentication are handled exclusively by Clerk.
 * Institutional school email verification is handled exclusively by autonomous School Servers.
 */
@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);

  constructor() {
    this.logger.log('📧 Central Server configured for 0 emails. Accounts managed strictly by Clerk.');
  }

  /**
   * No-op: Central server sends 0 emails.
   */
  async sendAccountVerificationCode(toEmail: string, code: string): Promise<boolean> {
    this.logger.warn(`[ZERO EMAILS POLICY] Ignored email dispatch request for ${toEmail}. Central server sends 0 emails.`);
    return true;
  }
}

