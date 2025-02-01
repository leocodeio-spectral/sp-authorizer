import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsMobilePhone } from 'class-validator';

export class VerifyMobileDto {
  @ApiProperty({
    description: 'Mobile number to verify',
    example: '+1234567890',
    required: true,
  })
  @IsString()
  @IsMobilePhone('en-US', { strictMode: false })
  mobile: string;
}

export class VerifyMobileConfirmDto extends VerifyMobileDto {
  @ApiProperty({
    description: 'OTP code received via SMS',
    example: '123456',
    required: true,
  })
  @IsString()
  code: string;
}
