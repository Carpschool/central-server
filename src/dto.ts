import { ApiProperty } from "@nestjs/swagger";
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsOptional,
  IsBoolean,
  IsInt,
  IsString,
  IsUrl,
  Length,
  Matches,
  MaxLength,
} from "class-validator";
export class OnboardDto {
  @ApiProperty()
  @IsUrl({ protocols: ["https"], require_protocol: true })
  @MaxLength(2048)
  baseUrl: string;
}
export class EnabledDto {
  @ApiProperty() @IsBoolean() enabled: boolean;
}
export class TicketDto {
  @ApiProperty()
  @IsString()
  @Matches(/^[a-zA-Z0-9_-]{2,64}$/)
  schoolCode: string;
}
export class HeartbeatDto extends TicketDto {
  @ApiProperty() @IsInt() timestamp: number;
  @ApiProperty()
  @IsString()
  @Length(16, 128)
  @Matches(/^[a-zA-Z0-9_-]+$/)
  nonce: string;
  @ApiProperty() @IsString() @Length(80, 100) signature: string;
}

export class SchoolUpdateDto {
  @ApiProperty({ required: false }) @IsOptional() @IsString() @Length(2, 200) name?: string;
  @ApiProperty({ required: false, type: [String] })
  @IsOptional()
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(30)
  @Matches(/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?[.])+[a-zA-Z]{2,63}$/, { each: true })
  domains?: string[];
  @ApiProperty({ required: false })
  @IsOptional()
  @IsUrl({ protocols: ["https"], require_protocol: true })
  @MaxLength(2048)
  baseUrl?: string;
}
export class AdminFlagDto {
  @ApiProperty() @IsBoolean() admin: boolean;
}

export class ClaimDto {
  @ApiProperty() @IsUrl({ protocols: ["https"], require_protocol: true }) @MaxLength(2048) baseUrl: string;
  @ApiProperty({ description: "7 hex chars from the school server log" }) @Matches(/^[0-9a-fA-F]{7}$/) code: string;
  @ApiProperty() @Matches(/^[a-z0-9_-]{2,64}$/) schoolCode: string;
  @ApiProperty() @IsString() @Length(2, 200) name: string;
}
export class CentralSettingsDto {
  @ApiProperty({ required: false }) @IsOptional() @IsString() @MaxLength(2048) publicUrl?: string;
  @ApiProperty({ required: false, type: [String] }) @IsOptional() @IsArray() @ArrayMaxSize(20) @IsString({ each: true }) @MaxLength(2048, { each: true }) corsOrigins?: string[];
}

export class LegalDto {
  @ApiProperty() @IsString() @MaxLength(100000) markdown: string;
}
