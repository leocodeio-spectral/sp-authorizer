import { Request } from 'express';

export const getCookieAccessToken = (request: Request) => {
  const cookies = request.headers.cookie.split(';');
  const accessToken = cookies.find((cookie) => cookie.includes('accessToken'));
  return accessToken;
};
