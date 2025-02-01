import { Body, Controller, Get, Post, Req } from '@nestjs/common';
import { ValidationService } from '../../application/services/validation.service';
import { IsPhoneValidDto } from '../../application/dtos/is-phone-valid.dto';
import { IsEmailValidDto } from '../../application/dtos/is-email-valid.dto';
import { ApiSecurity } from '@nestjs/swagger';
import { Request } from 'express';
import { ExistsPhoneDto } from '../../application/dtos/exists-phone.dto';
import { ExistsEmailDto } from '../../application/dtos/exists-email.dto';
import { UserRepository } from 'src/modules/authorization/domain/ports/user.repository';

@Controller('validate')
// @ApiSecurity('x-api-key')
export class ValidationController {
  constructor(
    private readonly validationService: ValidationService,
    private readonly userRepository: UserRepository,
  ) {}
  // IsPhone valid
  @Post('phone')
  async isPhoneValid(
    @Body() isPhoneValidDto: IsPhoneValidDto,
  ): Promise<boolean> {
    return this.validationService.isPhoneValid(isPhoneValidDto);
  }

  @Post('/exists/phone')
  async existsPhone(@Body() existsPhoneDto: ExistsPhoneDto): Promise<boolean> {
    const user = await this.userRepository.findByIdentifier(
      existsPhoneDto.phone,
    );
    return user !== null;
  }

  // IsEmail valid
  @Post('email')
  async isEmailValid(
    @Body() isEmailValidDto: IsEmailValidDto,
  ): Promise<boolean> {
    return this.validationService.isEmailValid(isEmailValidDto);
  }

  @Post('exists/email')
  async existsEmail(@Body() existsEmailDto: ExistsEmailDto): Promise<boolean> {
    const user = await this.userRepository.findByIdentifier(
      existsEmailDto.email,
    );
    return user !== null;
  }

  // IsAcessTokenValid
  // IsRefreshTokenValid
}
