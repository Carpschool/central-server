import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsInt, IsString, IsUrl, Length, Matches, MaxLength } from 'class-validator';
export class OnboardDto { @ApiProperty() @IsUrl({ protocols: ['https'], require_protocol: true }) @MaxLength(2048) baseUrl: string; }
export class TrustDto { @ApiProperty() @IsBoolean() trusted: boolean; }
export class TicketDto { @ApiProperty() @IsString() @Matches(/^[a-zA-Z0-9_-]{2,64}$/) schoolCode: string; }
export class HeartbeatDto extends TicketDto {
  @ApiProperty() @IsInt() timestamp: number;
  @ApiProperty() @IsString() @Length(16, 128) @Matches(/^[a-zA-Z0-9_-]+$/) nonce: string;
  @ApiProperty() @IsString() @Length(80, 100) signature: string;
}
