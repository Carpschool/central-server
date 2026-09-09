import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * @CurrentUser()
 * 
 * Custom parameter decorator to extract the authenticated user identity
 * populated by ClerkAuthGuard on the Express request object.
 * 
 * Usage:
 *   @Get('profile')
 *   getProfile(@CurrentUser() user: { userId: string }) { ... }
 */
export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);
