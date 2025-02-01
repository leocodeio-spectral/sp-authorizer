import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsIn } from 'class-validator';

export class ValidateTokenDto {
  @ApiProperty({
    description: 'Client channel making the request',
    enum: ['web', 'mobile', 'api'],
    example: 'api',
  })
  @IsString()
  @IsIn(['web', 'mobile', 'api'])
  channel: string;

  @ApiProperty({
    description: 'Client identifier (optional)',
    example: 'my-api-client-1',
  })
  @IsString()
  clientId?: string;
}
