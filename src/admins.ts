import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";
import { createClerkClient } from "@clerk/backend";
import { required } from "./config";
/** Thin Clerk wrapper so tests can replace it. */
@Injectable()
export class ClerkUsers {
  private c?: ReturnType<typeof createClerkClient>;
  private get client() {
    return (this.c ??= createClerkClient({ secretKey: required("CLERK_SECRET_KEY") }));
  }
  get(id: string) {
    return this.client.users.getUser(id);
  }
  list(query?: string) {
    return this.client.users.getUserList({ query: query || undefined, limit: 25, orderBy: "-created_at" });
  }
  setPrivate(id: string, privateMetadata: any) {
    return this.client.users.updateUser(id, { privateMetadata });
  }
}
export type Meta = { admin: boolean; school: Record<string, { admin: boolean }> };
export function normalize(pm: any): Meta {
  const school: Meta["school"] = {};
  if (pm?.school && typeof pm.school === "object")
    for (const [k, v] of Object.entries<any>(pm.school))
      if (/^[a-f0-9]{24}$/i.test(k)) school[k] = { admin: v?.admin === true };
  return { admin: pm?.admin === true, school };
}
export function view(u: any) {
  return {
    id: u.id,
    name: [u.firstName, u.lastName].filter(Boolean).join(" ") || u.username || null,
    email: u.primaryEmailAddress?.emailAddress ?? u.emailAddresses?.[0]?.emailAddress ?? null,
    imageUrl: u.imageUrl ?? null,
    ...normalize(u.privateMetadata),
  };
}
@Injectable()
export class AdminsService {
  constructor(private users: ClerkUsers) {}
  private async load(id: string) {
    if (!/^user_[A-Za-z0-9]{10,64}$/.test(id)) throw new BadRequestException("Invalid user id");
    try {
      return await this.users.get(id);
    } catch {
      throw new NotFoundException("User not found");
    }
  }
  async list(query?: string) {
    const r: any = await this.users.list(query?.slice(0, 100));
    return (r.data ?? r).map(view);
  }
  // Central (network) admin is changed ONLY in the Clerk dashboard; no API mutates privateMetadata.admin.
  async setSchool(id: string, schoolId: string, admin: boolean) {
    const u: any = await this.load(id);
    const m = normalize(u.privateMetadata);
    if (admin) m.school[schoolId] = { admin: true };
    else delete m.school[schoolId];
    // only the school map is written; privateMetadata.admin is left exactly as Clerk has it
    return view(await this.users.setPrivate(id, { ...u.privateMetadata, school: m.school }));
  }
}
