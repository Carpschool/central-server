import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { SchoolsService } from './schools.service';
import { OnboardSchoolDto } from './dto/onboard-school.dto';
import { CreateTicketDto } from './dto/create-ticket.dto';
import { ClerkAuthGuard } from '../../common/guards/clerk-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';

@ApiTags('schools')
@Controller('api/v1/schools')
export class SchoolsController {
  constructor(private readonly schoolsService: SchoolsService) {}

  /**
   * Admin automated school onboarding
   */
  @Post('admin/onboard')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Automated school onboarding by admin',
    description:
      'Takes a school server Base URL and Ed25519 Public Key, fetches /api/v1/meta from the school, verifies the signature, and auto-populates metadata.',
  })
  @ApiResponse({ status: 201, description: 'School verified and registered' })
  @ApiResponse({ status: 400, description: 'Signature or metadata verification failed' })
  async onboardSchool(@Body() dto: OnboardSchoolDto) {
    return this.schoolsService.onboardSchool(dto);
  }

  /**
   * Public directory of trusted schools
   */
  @Get()
  @ApiOperation({
    summary: 'List all trusted schools',
    description: 'Returns all verified schools for client discovery in the school picker.',
  })
  @ApiResponse({ status: 200, description: 'List of trusted schools' })
  async listSchools() {
    return this.schoolsService.listTrustedSchools();
  }

  /**
   * Get single school details
   */
  @Get(':code')
  @ApiOperation({ summary: 'Get single school metadata by school code' })
  @ApiResponse({ status: 200, description: 'School details' })
  @ApiResponse({ status: 404, description: 'School not found' })
  async getSchool(@Param('code') code: string) {
    return this.schoolsService.getSchoolByCode(code);
  }

  /**
   * Generate signed Federation Ticket
   */
  @Post('ticket')
  @UseGuards(ClerkAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Issue a signed Federation Ticket for connecting to a school server',
    description:
      'Validates Clerk auth and creates an Ed25519-signed ticket verifying student identity for trusted or untrusted school servers.',
  })
  @ApiResponse({ status: 200, description: 'Federation Ticket issued' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async issueTicket(
    @CurrentUser() user: any,
    @Body() dto: CreateTicketDto,
  ) {
    return this.schoolsService.issueFederationTicket(user, dto);
  }
}
