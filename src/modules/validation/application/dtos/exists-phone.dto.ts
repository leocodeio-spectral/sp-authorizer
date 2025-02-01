import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ExistsPhoneDto {
  @ApiProperty({
    description: 'Phone number to validate',
    example: '+94771234567',
  })
  @IsString()
  phone: string;
}
