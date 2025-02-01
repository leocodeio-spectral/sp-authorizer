import { ApiProperty } from '@nestjs/swagger';
import { DeviceInfoDto } from './login.dto';
import { IsString, IsMobilePhone, IsIn } from 'class-validator';

export class InitiateMobileLoginDto implements DeviceInfoDto {
  @ApiProperty({
    description: 'Mobile number for login',
    example: '+1234567890',
    required: true,
  })
  @IsString()
  @IsMobilePhone('en-US', { strictMode: false })
  mobile: string;

  @ApiProperty({
    description: 'Login channel',
    enum: ['web', 'mobile', 'api'],
    example: 'mobile',
    required: true,
  })
  @IsString()
  @IsIn(['web', 'mobile', 'api'])
  channel: string;

  @ApiProperty({
    description: 'User agent string',
    example: 'Mozilla/5.0...',
    required: false,
  })
  @IsString()
  userAgent?: string;
}

export class CompleteMobileLoginDto extends InitiateMobileLoginDto {
  @ApiProperty({
    description: 'OTP code received via SMS',
    example: '123456',
    required: true,
  })
  @IsString()
  otp: string;
}
