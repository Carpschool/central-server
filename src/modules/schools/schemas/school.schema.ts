import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type SchoolDocument = School & Document;

/**
 * Mongoose Schema representing a registered school/university in Central Server.
 */
@Schema({ timestamps: true, collection: 'schools' })
export class School {
  @Prop({ required: true, unique: true, index: true })
  schoolCode: string; // e.g. "ubc", "sfu"

  @Prop({ required: true })
  officialName: string; // e.g. "University of British Columbia"

  @Prop({ type: [String], default: [] })
  allowedEmailDomains: string[]; // e.g. ["ubc.ca", "student.ubc.ca"]

  @Prop({ required: true })
  baseUrl: string; // e.g. "https://ubc.carp.school"

  @Prop({ required: true })
  ed25519PublicKey: string; // Base64 public key of the school server

  @Prop({ default: true })
  isTrusted: boolean; // Flagged true when onboarded by central admin

  @Prop({
    type: {
      address: String,
      latitude: Number,
      longitude: Number,
    },
    default: null,
  })
  campusLocation?: {
    address: string;
    latitude: number;
    longitude: number;
  };

  @Prop({ default: null })
  logoUrl?: string;

  @Prop({ default: Date.now })
  lastHeartbeat: Date;
}

export const SchoolSchema = SchemaFactory.createForClass(School);
