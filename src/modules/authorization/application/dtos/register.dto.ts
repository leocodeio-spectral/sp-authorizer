import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsString,
  IsIn,
  MinLength,
  Matches,
  IsMobilePhone,
  IsOptional,
} from 'class-validator';
import { user_status } from 'src/auth/domain/enums/user_status.enum';

export class RegisterDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
    required: true,
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'User mobile number',
    example: '12543008333',
    required: true,
  })
  @IsMobilePhone()
  mobile: string;

  @ApiProperty({
    description:
      'User password - must be at least 12 characters and contain uppercase, lowercase, number, special character',
    example: 'SecurePass123!',
    required: true,
    minLength: 12,
  })
  @IsString()
  @MinLength(12)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/,
    {
      message:
        'Password must contain uppercase, lowercase, number, special character',
    },
  )
  password: string;

  @ApiProperty({
    description: 'Registration channel',
    enum: ['web', 'mobile', 'api'],
    example: 'web',
    required: true,
  })
  @IsString()
  @IsIn(['web', 'mobile', 'api'])
  channel: string;

  @ApiProperty({
    description: 'Mobile verification code',
    example: '123456',
    required: false,
  })
  @IsString()
  @IsOptional()
  mobileVerificationCode?: string;

  @ApiProperty({
    description: 'User first name',
    example: 'John',
    required: true,
  })
  @IsString()
  firstName: string;

  @ApiProperty({
    description: 'User last name',
    example: 'Doe',
    required: true,
  })
  @IsString()
  lastName: string;

  @ApiProperty({
    description: 'User profile picture URL',
    example: 'https://example.com/profile.jpg',
    required: false,
  })
  @IsString()
  @IsOptional()
  profilePicUrl?: string;

  @ApiProperty({
    description: 'User language',
    example: 'en',
    required: false,
  })
  @IsString()
  @IsOptional()
  language?: string;

  @ApiProperty({
    description: 'User time zone',
    example: 'UTC',
    required: false,
  })
  @IsString()
  @IsOptional()
  timeZone?: string;
}
