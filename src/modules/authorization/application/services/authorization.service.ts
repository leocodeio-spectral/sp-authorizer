import { Injectable } from '@nestjs/common';
import { Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { AuthorizeRequestDto } from '../dtos/authorize-request.dto';

@Injectable()
export class AuthorizationService {
  constructor() {}

  // Provide Access Token to user
  async provideAccessToken(
    provideAccessTokenDto: AuthorizeRequestDto,
    response: Response,
  ): Promise<void> {
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
  }

  // Provide Refresh Token to user
  async provideRefreshToken(
    provideRefreshTokenDto: AuthorizeRequestDto,
    response: Response,
  ): Promise<void> {
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
  }

  async authorizeUser(
    authorizeRequestDto: AuthorizeRequestDto,
    response: Response,
  ): Promise<void> {
    const accessToken = this.provideAccessToken(authorizeRequestDto, response);
    const refreshToken = this.provideRefreshToken(
      authorizeRequestDto,
      response,
    );
  }
}
