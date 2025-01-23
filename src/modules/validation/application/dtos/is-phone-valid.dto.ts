import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class IsPhoneValidDto {
  @ApiProperty({
    description: 'Phone number to validate',
    example: '+94771234567'
  })
  @IsString()
  phoneNumber: string;

  @ApiProperty({
    description: 'Country code for the phone number',
    example: 'LK'
  })
  @IsString()
  countryCode: string;
}
