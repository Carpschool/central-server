import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

/**
 * Global User record stored in Central Server database (central_db).
 */
@Schema({ timestamps: true, collection: 'users' })
export class User {
  @Prop({ required: true, unique: true, index: true })
  clerkUserId: string; // The primary immutable Clerk User ID (e.g. user_2n...)

  @Prop({ required: true, unique: true, index: true })
  primaryEmail: string;

  @Prop({ required: true })
  fullName: string;

  @Prop({ default: null })
  phoneNumber?: string;

  @Prop({ default: false })
  isCentralEmailVerified: boolean;

  @Prop({ default: null })
  avatarUrl?: string;

  @Prop({ default: Date.now })
  lastLoginAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
