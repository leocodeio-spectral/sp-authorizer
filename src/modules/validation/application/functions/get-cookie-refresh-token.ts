import { UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';

export const getCookieRefreshToken = (request: Request) => {
  if (!request.headers.cookie) {
    throw new UnauthorizedException('No cookie found');
  }
  const cookies = request.headers.cookie.split(';');
  const refreshToken = cookies.find((cookie) =>
    cookie.includes('refreshToken'),
  );
  if (!refreshToken) {
    throw new UnauthorizedException('No refresh token found');
  }
  return refreshToken.split('=')[1];
};
