import {
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';

import { PhoneNumberUtil } from 'google-libphonenumber';
import { IsPhoneValidDto } from '../dtos/is-phone-valid.dto';
const phoneUtil = PhoneNumberUtil.getInstance();

import * as EmailValidator from 'email-validator';
import { IsEmailValidDto } from '../dtos/is-email-valid.dto';

import * as jwt from 'jsonwebtoken';
import { Request } from 'express';
import { getCookieAccessToken } from '../functions/get-cookie-access-token';
import { getCookieRefreshToken } from '../functions/get-cookie-refresh-token';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class ValidationService {
  constructor(private readonly configService: ConfigService) {}

  async isPhoneValid(isPhoneValidDto: IsPhoneValidDto): Promise<boolean> {
    try {
      const phoneNumber = phoneUtil.parse(
        isPhoneValidDto.phoneNumber,
        isPhoneValidDto.countryCode,
      );
      return phoneUtil.isValidNumber(phoneNumber);
    } catch (error) {
      // console.log('+++++++++++++++++++++++');
      // console.log(error.message);
      // console.log('+++++++++++++++++++++++');
      throw new InternalServerErrorException(error.message);
    }
  }

  async isEmailValid(isEmailValidDto: IsEmailValidDto): Promise<boolean> {
    return EmailValidator.validate(isEmailValidDto.email);
  }

  async isAccessTokenValid(request: Request): Promise<boolean> {
    try {
      const accessToken = getCookieAccessToken(request);
      jwt.verify(accessToken, this.configService.get('ACCESS_TOKEN_SECRET'));
      return true;
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  }

  async isRefreshTokenValid(request: Request): Promise<boolean> {
    try {
      const refreshToken = getCookieRefreshToken(request);
      jwt.verify(refreshToken, this.configService.get('REFRESH_TOKEN_SECRET'));
      return true;
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  }
}
