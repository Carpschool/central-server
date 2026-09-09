import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsUrl } from 'class-validator';

/**
 * OnboardSchoolDto
 * 
 * Data transfer object for administrator automated school onboarding.
 * Admins provide only the School Base URL and Ed25519 Public Key.
 * All other metadata (name, code, domains, location) is fetched and verified automatically.
 */
export class OnboardSchoolDto {
  @ApiProperty({
    description: 'The public base URL of the school server',
    example: 'https://ubc.carp.school',
  })
  @IsUrl({ require_tld: false }, { message: 'baseUrl must be a valid URL' })
  @IsNotEmpty()
  baseUrl: string;

  @ApiProperty({
    description: 'The 32-byte Ed25519 public key of the school server (Base64 encoded)',
    example: '7q2w...YOUR_BASE64_ED25519_KEY...',
  })
  @IsString()
  @IsNotEmpty()
  ed25519PublicKey: string;
}
