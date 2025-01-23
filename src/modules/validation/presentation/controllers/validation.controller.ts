import { Body, Controller, Get, Post } from '@nestjs/common';
import { ValidationService } from '../../application/services/validation.service';
import { IsPhoneValidDto } from '../../application/dtos/is-phone-valid.dto';
import { IsEmailValidDto } from '../../application/dtos/is-email-valid.dto';
import { IsAccessTokenValidDto } from '../../application/dtos/is-access-token-valid.dto';
import { IsRefreshTokenValidDto } from '../../application/dtos/is-refresh-token-valid.dto';

@Controller('validation')
export class ValidationController {
  constructor(private readonly validationService: ValidationService) {}

  @Get()
  getHello(): string {
    return this.validationService.getHello();
  }

  // IsPhone valid
  @Post('phone')
  async isPhoneValid(
    @Body() isPhoneValidDto: IsPhoneValidDto,
  ): Promise<boolean> {
    return this.validationService.isPhoneValid(isPhoneValidDto);
  }

  // IsEmail valid
  @Post('email')
  async isEmailValid(
    @Body() isEmailValidDto: IsEmailValidDto,
  ): Promise<boolean> {
    return this.validationService.isEmailValid(isEmailValidDto);
  }

  // IsAcessTokenValid
  @Post('access-token')
  async isAccessTokenValid(
    @Body() isAccessTokenValidDto: IsAccessTokenValidDto,
  ): Promise<boolean> {
    return this.validationService.isAccessTokenValid(isAccessTokenValidDto);
  }

  // IsRefreshTokenValid
  @Post('refresh-token')
  async isRefreshTokenValid(
    @Body() isRefreshTokenValidDto: IsRefreshTokenValidDto,
  ): Promise<boolean> {
    return this.validationService.isRefreshTokenValid(isRefreshTokenValidDto);
  }
}
