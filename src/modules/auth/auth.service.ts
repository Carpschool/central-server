import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './schemas/user.schema';
import { SyncUserDto } from './dto/sync-user.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  /**
   * Synchronizes Clerk authenticated user identity with the global users collection.
   */
  async syncUser(clerkUserId: string, dto: SyncUserDto): Promise<User> {
    const user = await this.userModel.findOneAndUpdate(
      { clerkUserId },
      {
        clerkUserId,
        primaryEmail: dto.email.toLowerCase(),
        fullName: dto.fullName,
        phoneNumber: dto.phoneNumber || null,
        avatarUrl: dto.avatarUrl || null,
        lastLoginAt: new Date(),
      },
      { upsert: true, new: true },
    );

    this.logger.log(`Synchronized global user: ${user.primaryEmail} (${user.clerkUserId})`);
    return user;
  }

  /**
   * Finds a global user by their Clerk User ID.
   */
  async getUserByClerkId(clerkUserId: string): Promise<User | null> {
    return this.userModel.findOne({ clerkUserId }).exec();
  }
}
