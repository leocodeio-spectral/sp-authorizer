import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class IsAccessTokenValidDto {
  @ApiProperty({
    description: 'Access token to validate',
    example: 'test@example.com',
  })
  @IsString()
  accessToken: string;
}
