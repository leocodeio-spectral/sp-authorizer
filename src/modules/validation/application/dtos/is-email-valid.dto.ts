import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class IsEmailValidDto {
  @ApiProperty({
    description: 'Email to validate',
    example: 'test@example.com',
  })
  @IsString()
  @IsNotEmpty()
  email: string;
}
