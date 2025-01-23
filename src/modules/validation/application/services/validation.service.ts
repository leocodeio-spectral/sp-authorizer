import { Injectable, InternalServerErrorException } from '@nestjs/common';

import { PhoneNumberUtil } from 'google-libphonenumber';
import { IsPhoneValidDto } from '../dtos/is-phone-valid.dto';
const phoneUtil = PhoneNumberUtil.getInstance();

import * as EmailValidator from 'email-validator';
import { IsEmailValidDto } from '../dtos/is-email-valid.dto';

import { IsAccessTokenValidDto } from '../dtos/is-access-token-valid.dto';
import * as jwt from 'jsonwebtoken';
import { IsRefreshTokenValidDto } from '../dtos/is-refresh-token-valid.dto';

@Injectable()
export class ValidationService {
  constructor() {}

  getHello(): string {
    return 'Hello World!';
  }

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

  async isAccessTokenValid(
    isAccessTokenValidDto: IsAccessTokenValidDto,
  ): Promise<boolean> {
    jwt.verify(
      isAccessTokenValidDto.accessToken,
      process.env.ACCESS_TOKEN_SECRET,
      function (err, decoded) {
        if (err) {
          /*
            err = {
              name: 'TokenExpiredError',
              message: 'jwt expired',
              expiredAt: 1408621000
            }
          */
          return false;
        }
      },
    );
    return true;
  }

  async isRefreshTokenValid(
    isRefreshTokenValidDto: IsRefreshTokenValidDto,
  ): Promise<boolean> {
    jwt.verify(
      isRefreshTokenValidDto.refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      function (err, decoded) {
        if (err) {
          /*
            err = {
              name: 'TokenExpiredError',
              message: 'jwt expired',
              expiredAt: 1408621000
            }
          */
          return false;
        }
      },
    );
    return true;
  }
}
