import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { createClerkClient, verifyToken } from "@clerk/backend";
import { required } from "./config";
@Injectable()
export class IdentityService {
  client = createClerkClient({ secretKey: required("CLERK_SECRET_KEY") });
  async authenticate(header?: string) {
    if (!header?.startsWith("Bearer ")) throw new UnauthorizedException();
    try {
      const claims = await verifyToken(header.slice(7), {
        secretKey: required("CLERK_SECRET_KEY"),
        authorizedParties: required("CLERK_AUTHORIZED_PARTIES")
          .split(",")
          .map((s) => s.trim()),
      });
      if (!claims.sub || !claims.sid) throw new Error("Not a session token");
      return await this.client.users.getUser(claims.sub);
    } catch {
      throw new UnauthorizedException("Invalid Clerk session");
    }
  }
}
@Injectable()
export class ClerkGuard implements CanActivate {
  constructor(private identity: IdentityService) {}
  async canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest();
    req.identity = await this.identity.authenticate(req.headers.authorization);
    return true;
  }
}
@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(ctx: ExecutionContext) {
    if (
      ctx.switchToHttp().getRequest().identity?.privateMetadata?.admin !== true
    )
      throw new ForbiddenException("Central admin required");
    return true;
  }
}
