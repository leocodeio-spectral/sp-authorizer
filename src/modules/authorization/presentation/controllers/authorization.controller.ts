import { Body, Controller, Get, Post, Res } from '@nestjs/common';
import { AuthorizationService } from '../../application/services/authorization.service';
import { ProvideAccessTokenDto } from '../../application/dtos/provide-access-token.dto';
import { ProvideRefreshTokenDto } from '../../application/dtos/provide-refresh-token.dto';
import { RefreshTokenResponseType } from '../../domain/types/acess-token-response.type';
import { Response } from 'express';
import { AccessTokenResponseType } from '../../domain/types/acess-token-response.type copy';

@Controller('authorize')
export class AuthorizationController {
  constructor(private readonly authorizationService: AuthorizationService) {}

  // Provide Access Token to user
  @Post('access-token')
  async provideAccessToken(
    @Body() provideAccessTokenDto: ProvideAccessTokenDto,
    @Res() response: Response,
  ): Promise<void> {
    const result = await this.authorizationService.provideAccessToken(
      provideAccessTokenDto,
      response,
    );
    response.json(result);
  }

  // Provide Refresh Token to user
  @Post('refresh-token')
  async provideRefreshToken(
    @Body() provideRefreshTokenDto: ProvideRefreshTokenDto,
    @Res() response: Response,
  ): Promise<void> {
    const result = await this.authorizationService.provideRefreshToken(
      provideRefreshTokenDto,
      response,
    );
    response.json(result);
  }
}
