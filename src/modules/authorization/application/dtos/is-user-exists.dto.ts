import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsIn } from 'class-validator';

export class IsUserExistsDto {
  @ApiProperty({
    description: 'User identifier (email or mobile)',
    example: 'user@example.com or +1234567890',
    required: true,
  })
  @IsString()
  identifier: string;

  @ApiProperty({
    description: 'User type (email or mobile)',
    example: 'email or mobile',
    required: true,
  })
  @IsString()
  @IsIn(['email', 'mobile'])
  type: 'email' | 'mobile';
}
