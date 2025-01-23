import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ProvideRefreshTokenDto {
  @ApiProperty({
    description: 'User ID to generate refresh token',
    example: '1234567890',
  })
  @IsString()
  userId: string;
}
