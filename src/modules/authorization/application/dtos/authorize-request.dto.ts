import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AuthorizeRequestDto {
  @ApiProperty({
    description: 'User ID to generate access token',
    example: '1234567890',
  })
  @IsString()
  userId: string;
}
