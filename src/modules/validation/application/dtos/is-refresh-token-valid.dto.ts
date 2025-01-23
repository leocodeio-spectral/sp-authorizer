import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class IsRefreshTokenValidDto {
  @ApiProperty({
    description: 'Refresh token to validate',
    example: 'test@example.com',
  })
  @IsString()
  refreshToken: string;
}
