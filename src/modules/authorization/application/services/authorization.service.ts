import { Injectable } from '@nestjs/common';
import { ProvideAccessTokenDto } from '../dtos/provide-access-token.dto';
import { ProvideRefreshTokenDto } from '../dtos/provide-refresh-token.dto';
import { Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { RefreshTokenResponseType } from '../../domain/types/acess-token-response.type';
import { AccessTokenResponseType } from '../../domain/types/acess-token-response.type copy';

@Injectable()
export class AuthorizationService {
  constructor() {}

  // Provide Access Token to user
  async provideAccessToken(
    provideAccessTokenDto: ProvideAccessTokenDto,
    response: Response,
  ): Promise<AccessTokenResponseType> {
    const accessToken = jwt.sign(
      { userId: provideAccessTokenDto.userId },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: '1h',
      },
    );
    response.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000,
    });
    return { accessToken };
  }

  // Provide Refresh Token to user
  async provideRefreshToken(
    provideRefreshTokenDto: ProvideRefreshTokenDto,
    response: Response,
  ): Promise<RefreshTokenResponseType> {
    const refreshToken = jwt.sign(
      { userId: provideRefreshTokenDto.userId },
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: '1d',
      },
    );
    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 86400000,
    });
    return { refreshToken };
  }
}
