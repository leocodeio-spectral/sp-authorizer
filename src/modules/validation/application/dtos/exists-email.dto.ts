import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ExistsEmailDto {
  @ApiProperty({
    description: 'Email to validate',
    example: 'test@example.com',
  })
  @IsString()
  email: string;
}
