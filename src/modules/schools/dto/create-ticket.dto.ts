import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

/**
 * CreateTicketDto
 * 
 * Request DTO for generating a signed Federation Ticket.
 * Supports both trusted registered school codes and custom untrusted school URLs.
 */
export class CreateTicketDto {
  @ApiProperty({
    description: 'Unique school code (e.g. "ubc") for trusted registered schools, or "custom"',
    example: 'ubc',
  })
  @IsString()
  @IsNotEmpty()
  schoolCode: string;

  @ApiProperty({
    description: 'Optional manual Base URL for custom/untrusted self-hosted school servers',
    example: 'https://rides.myschool.org',
    required: false,
  })
  @IsOptional()
  @IsString()
  customBaseUrl?: string;
}
