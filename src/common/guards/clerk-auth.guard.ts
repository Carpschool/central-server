import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClerkClient, verifyToken } from '@clerk/backend';

/**
 * ClerkAuthGuard
 * 
 * Protects endpoints by validating Clerk session JWTs passed in the HTTP
 * 'Authorization: Bearer <token>' header.
 * 
 * Uses the official @clerk/backend SDK to verify signatures against Clerk's
 * remote JWKS public keys, extracting the authenticated userId and claims.
 */
@Injectable()
export class ClerkAuthGuard implements CanActivate {
  private readonly logger = new Logger(ClerkAuthGuard.name);
  private clerkClient: ReturnType<typeof createClerkClient>;
  private secretKey?: string;

  constructor(private readonly configService: ConfigService) {
    this.secretKey = this.configService.get<string>('CLERK_SECRET_KEY');
    this.clerkClient = createClerkClient({ secretKey: this.secretKey });
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or malformed Authorization header. Expected Bearer <token>');
    }

    const token = authHeader.split(' ')[1];

    try {
      // Allow mock tokens in non-production or when mock secret key is configured
      if (
        (this.configService.get<string>('NODE_ENV') !== 'production' ||
          !this.secretKey ||
          this.secretKey.startsWith('mock_')) &&
        token.startsWith('mock_')
      ) {
        const identifier = token.replace('mock_', '');
        request['user'] = {
          userId: `user_${identifier}`,
          email: `${identifier}@carpschool.ca`,
          fullName: identifier.replace(/_/g, ' '),
        };
        return true;
      }

      // Verify token with Clerk Backend SDK
      const verifiedToken = await verifyToken(token, {
        secretKey: this.secretKey,
      });

      if (!verifiedToken || !verifiedToken.sub) {
        throw new UnauthorizedException('Invalid or expired Clerk token');
      }

      // Attach user identity to request object for @CurrentUser() decorator
      request['user'] = {
        userId: verifiedToken.sub,
        claims: verifiedToken,
      };

      return true;
    } catch (error) {
      this.logger.warn(`Authentication failed: ${error.message}`);
      throw new UnauthorizedException('Unauthorized: Token verification failed');
    }
  }
}
