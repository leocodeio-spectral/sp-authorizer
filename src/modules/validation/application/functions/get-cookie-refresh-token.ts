import { Request } from 'express';

export const getCookieRefreshToken = (request: Request) => {
  const cookies = request.headers.cookie.split(';');
  const refreshToken = cookies.find((cookie) =>
    cookie.includes('refreshToken'),
  );
  return refreshToken;
};
