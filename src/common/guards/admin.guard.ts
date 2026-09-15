import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../../modules/auth/schemas/user.schema';

/**
 * AdminGuard
 * 
 * Enforces that the requesting user is an administrator.
 * Admin status is defined strictly via Clerk private metadata ("admin": true).
 */
@Injectable()
export class AdminGuard implements CanActivate {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user || !user.userId) {
      throw new ForbiddenException('Admin access required: User identity not found');
    }

    if (user.admin === true) {
      return true;
    }

    const dbUser = await this.userModel.findOne({ clerkUserId: user.userId }).exec();
    if (dbUser && dbUser.admin === true) {
      user.admin = true;
      return true;
    }

    throw new ForbiddenException('Forbidden: Administrator privileges required');
  }
}
