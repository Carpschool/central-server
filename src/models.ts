import { Schema } from 'mongoose';
export const SchoolSchema = new Schema({ schoolCode: { type: String, required: true, unique: true }, name: { type: String, required: true }, domains: [String], baseUrl: String, publicKey: String, trusted: { type: Boolean, default: false }, lastHeartbeat: Date }, { timestamps: true });
export const ReplaySchema = new Schema({ key: { type: String, unique: true, required: true }, expiresAt: { type: Date, expires: 0, required: true } });
export const UserSchema = new Schema({ clerkId: { type: String, unique: true, required: true }, name: String, avatar: String, deleted: Boolean, eventTimestamp: Number }, { timestamps: true });
