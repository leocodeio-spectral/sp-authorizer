import { Body, Controller, Get, Post, Res } from '@nestjs/common';
import { AuthorizationService } from '../../application/services/authorization.service';
import { Response } from 'express';
import { AuthorizeRequestDto } from '../../application/dtos/authorize-request.dto';

@Controller('authorize')
export class AuthorizationController {
  constructor(private readonly authorizationService: AuthorizationService) {}

  // Provide Access Token to user
  // @Post('access-token')
  // async provideAccessToken(
  //   @Body() provideAccessTokenDto: ProvideAccessTokenDto,
  //   @Res() response: Response,
  // ): Promise<void> {
  //   const result = await this.authorizationService.provideAccessToken(
  //     provideAccessTokenDto,
  //     response,
  //   );
  //   response.json(result);
  // }

  // Provide Refresh Token to user
  // @Post('refresh-token')
  // async provideRefreshToken(
  //   @Body() provideRefreshTokenDto: ProvideRefreshTokenDto,
  //   @Res() response: Response,
  // ): Promise<void> {
  //   const result = await this.authorizationService.provideRefreshToken(
  //     provideRefreshTokenDto,
  //     response,
  //   );
  //   response.json(result);
  // }

  @Post('authorize-user')
  async authorizeUser(
    @Body() authorizeRequestDto: AuthorizeRequestDto,
    @Res() response: Response,
  ): Promise<void> {
    await this.authorizationService.authorizeUser(
      authorizeRequestDto,
      response,
    );
    response.status(200).json({ data: 'User authorized' });
  }

  @Get('revoke-token')
  async revokeToken(@Res() response: Response): Promise<void> {
    response.clearCookie('accessToken');
    response.clearCookie('refreshToken');
    response.status(200).json({ data: 'Token revoked' });
  }
}
  