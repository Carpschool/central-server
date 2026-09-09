import { Controller, Post, Get, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { SyncUserDto } from './dto/sync-user.dto';
import { ClerkAuthGuard } from '../../common/guards/clerk-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';

@ApiTags('auth')
@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sync')
  @UseGuards(ClerkAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Sync Clerk User Profile with Central Database',
    description: 'Upserts global student profile in central_db using verified Clerk token.',
  })
  @ApiResponse({ status: 200, description: 'Profile synchronized' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async syncUser(
    @CurrentUser() user: any,
    @Body() dto: SyncUserDto,
  ) {
    return this.authService.syncUser(user.userId, dto);
  }

  @Get('me')
  @UseGuards(ClerkAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current global user profile' })
  @ApiResponse({ status: 200, description: 'Current user profile' })
  async getCurrentUser(@CurrentUser() user: any) {
    return this.authService.getUserByClerkId(user.userId);
  }
}
