import { UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';

export const getCookieAccessToken = (request: Request) => {
  if (!request.headers.cookie) {
    throw new UnauthorizedException('No cookie found');
  }
  const cookies = request.headers.cookie.split(';');
  const accessToken = cookies.find((cookie) => cookie.includes('accessToken'));
  if (!accessToken) {
    throw new UnauthorizedException('No access token found');
  }
  return accessToken.split('=')[1];
};
