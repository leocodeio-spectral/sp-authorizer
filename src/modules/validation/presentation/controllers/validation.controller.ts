import { Body, Controller, Get, Post, Req } from '@nestjs/common';
import { ValidationService } from '../../application/services/validation.service';
import { IsPhoneValidDto } from '../../application/dtos/is-phone-valid.dto';
import { IsEmailValidDto } from '../../application/dtos/is-email-valid.dto';
import { ApiSecurity } from '@nestjs/swagger';
import { Request } from 'express';

@Controller('validate')
// @ApiSecurity('x-api-key')
export class ValidationController {
  constructor(private readonly validationService: ValidationService) {}
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
  @Get('access-token')
  async isAccessTokenValid(
    @Req() request: Request,
  ): Promise<boolean> {
    return this.validationService.isAccessTokenValid(request);
  }

  // IsRefreshTokenValid
  @Get('refresh-token')
  async isRefreshTokenValid(
    @Req() request: Request,
  ): Promise<boolean> {
    return this.validationService.isRefreshTokenValid(request);
  }
}
