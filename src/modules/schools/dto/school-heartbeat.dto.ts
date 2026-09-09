import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber, IsOptional, IsString } from 'class-validator';

export class SchoolHeartbeatDto {
  @ApiProperty({ example: 'ubc', description: 'School code' })
  @IsString()
  @IsNotEmpty()
  schoolCode: string;

  @ApiProperty({ example: '2026-09-09T06:00:00.000Z', description: 'Timestamp when heartbeat was sent' })
  @IsString()
  @IsNotEmpty()
  timestamp: string;

  @ApiProperty({ example: 12, description: 'Number of active carpools currently running', required: false })
  @IsNumber()
  @IsOptional()
  activeCarpools?: number;

  @ApiProperty({ example: 45, description: 'Number of active students currently on the platform', required: false })
  @IsNumber()
  @IsOptional()
  activeStudents?: number;

  @ApiProperty({ example: '2.0.0', description: 'School server software version', required: false })
  @IsString()
  @IsOptional()
  version?: string;
}
