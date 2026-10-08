import { Schema } from "mongoose";
export const SchoolSchema = new Schema(
  {
    schoolCode: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    domains: [String],
    baseUrl: String,
    publicKey: String,
    trusted: { type: Boolean, default: false },
    /** Network admin on/off switch. Every registered school is trusted; disabled ones are hidden and get no tickets. */
    enabled: { type: Boolean, default: true },
    lastHeartbeat: Date,
    metaSyncedAt: Date,
  },
  { timestamps: true },
);
export const ReplaySchema = new Schema({
  key: { type: String, unique: true, required: true },
  expiresAt: { type: Date, expires: 0, required: true },
});
export const UserSchema = new Schema(
  {
    clerkId: { type: String, unique: true, required: true },
    name: String,
    avatar: String,
    deleted: Boolean,
    /** School _ids this user has opened a session with (recorded when a ticket is issued). */
    schools: { type: [String], default: [] },
    eventTimestamp: Number,
  },
  { timestamps: true },
);
