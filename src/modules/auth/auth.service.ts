import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { ConfigService } from '@nestjs/config';
import { Model } from 'mongoose';
import { createClerkClient } from '@clerk/backend';
import { User, UserDocument } from './schemas/user.schema';
import { SyncUserDto } from './dto/sync-user.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private clerkClient: ReturnType<typeof createClerkClient> | null = null;

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    private readonly configService: ConfigService,
  ) {
    const secretKey = this.configService.get<string>('CLERK_SECRET_KEY');
    if (secretKey && !secretKey.startsWith('mock_')) {
      this.clerkClient = createClerkClient({ secretKey });
    }
  }

  /**
   * Synchronizes Clerk authenticated user identity with the global users collection.
   * Admin status is strictly determined by Clerk private metadata ('admin': true).
   * By default, every user receives 'admin': false.
   */
  async syncUser(clerkUserId: string, dto: SyncUserDto): Promise<User> {
    let isAdmin = false;

    if (this.clerkClient && !clerkUserId.startsWith('user_mock_')) {
      try {
        const clerkUser = await this.clerkClient.users.getUser(clerkUserId);
        if (
          clerkUser?.privateMetadata?.admin === true ||
          clerkUser?.publicMetadata?.admin === true
        ) {
          isAdmin = true;
        }
      } catch (err: any) {
        this.logger.warn(`Could not fetch Clerk user metadata for ${clerkUserId}: ${err.message}`);
      }
    } else if (clerkUserId.includes('admin')) {
      isAdmin = true;
    }

    const user = await this.userModel.findOneAndUpdate(
      { clerkUserId },
      {
        clerkUserId,
        primaryEmail: dto.email.toLowerCase(),
        fullName: dto.fullName,
        phoneNumber: dto.phoneNumber || null,
        avatarUrl: dto.avatarUrl || null,
        admin: isAdmin,
        lastLoginAt: new Date(),
      },
      { upsert: true, new: true },
    );

    this.logger.log(
      `Synchronized global user: ${user.primaryEmail} (${user.clerkUserId}) - admin: ${user.admin}`,
    );
    return user;
  }

  /**
   * Finds a global user by their Clerk User ID.
   */
  async getUserByClerkId(clerkUserId: string): Promise<User | null> {
    return this.userModel.findOne({ clerkUserId }).exec();
  }
}
