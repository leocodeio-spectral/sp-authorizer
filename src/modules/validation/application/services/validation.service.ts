import { Injectable, InternalServerErrorException } from '@nestjs/common';

import { PhoneNumberUtil } from 'google-libphonenumber';
import { IsPhoneValidDto } from '../dtos/is-phone-valid.dto';
const phoneUtil = PhoneNumberUtil.getInstance();

import * as EmailValidator from 'email-validator';
import { IsEmailValidDto } from '../dtos/is-email-valid.dto';

import * as jwt from 'jsonwebtoken';
import { Request } from 'express';
import { getCookieAccessToken } from '../functions/get-cookie-access-token';

@Injectable()
export class ValidationService {
  constructor() {}

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
    const accessToken = getCookieAccessToken(request);
    jwt.verify(
      accessToken,
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

  async isRefreshTokenValid(request: Request): Promise<boolean> {
    const refreshToken = request.cookies['refreshToken'];
    jwt.verify(
      refreshToken,
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
