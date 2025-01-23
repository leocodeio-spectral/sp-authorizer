import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { AuthorizeRequestDto } from '../dtos/authorize-request.dto';
import { ConfigService } from '@nestjs/config';
import { parseTimeToMs } from '../functions/parse-time-to-ms';
import { getCookieRefreshToken } from 'src/modules/validation/application/functions/get-cookie-refresh-token';

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

  async refreshUser(request: Request, response: Response): Promise<void> {
    try {
      const refreshToken = getCookieRefreshToken(request);
      const decoded = jwt.verify(
        refreshToken,
        this.configService.get('REFRESH_TOKEN_SECRET'),
      ) as AuthorizeRequestDto;

      const authorizeRequestDto: AuthorizeRequestDto = {
        userId: decoded.userId,
      };

      // this gets called if the refresh token is valid
      this.provideAccessToken(authorizeRequestDto, response);
    } catch (error) {
      // this gets called if the refresh token is expired or invalid
      throw new UnauthorizedException(error.message);
    }
  }
}
