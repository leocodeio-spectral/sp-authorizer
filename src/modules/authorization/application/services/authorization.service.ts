import { Injectable } from '@nestjs/common';
import { Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { AuthorizeRequestDto } from '../dtos/authorize-request.dto';
import { ConfigService } from '@nestjs/config';
import { parseTimeToMs } from '../functions/parse-time-to-ms';

@Injectable()
export class AuthorizationService {
  constructor(private readonly configService: ConfigService) {}

  // Provide Access Token to user
  async provideAccessToken(
    provideAccessTokenDto: AuthorizeRequestDto,
    response: Response,
  ): Promise<void> {
    const accessToken = jwt.sign(
      { userId: provideAccessTokenDto.userId },
      this.configService.get('ACCESS_TOKEN_SECRET'),
      {
        expiresIn: this.configService.get('ACCESS_TOKEN_EXPIRATION_TIME'),
      },
    );

    // Convert time string to milliseconds
    const maxAge = parseTimeToMs(
      this.configService.get('ACCESS_TOKEN_EXPIRATION_TIME'),
    );

    response.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge,
    });
  }

  // Provide Refresh Token to user
  async provideRefreshToken(
    provideRefreshTokenDto: AuthorizeRequestDto,
    response: Response,
  ): Promise<void> {
    const refreshToken = jwt.sign(
      { userId: provideRefreshTokenDto.userId },
      this.configService.get('REFRESH_TOKEN_SECRET'),
      {
        expiresIn: this.configService.get('REFRESH_TOKEN_EXPIRATION_TIME'),
      },
    );

    // Convert time string to milliseconds
    const maxAge = parseTimeToMs(
      this.configService.get('REFRESH_TOKEN_EXPIRATION_TIME'),
    );

    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge,
    });
  }

  async authorizeUser(
    authorizeRequestDto: AuthorizeRequestDto,
    response: Response,
  ): Promise<void> {
    this.provideAccessToken(authorizeRequestDto, response);
    this.provideRefreshToken(authorizeRequestDto, response);
  }
}
