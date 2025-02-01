import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
} from '@nestjs/common';
import { RateLimiterMemory } from 'rate-limiter-flexible';

@Injectable()
export class IpRateLimitGuard implements CanActivate {
  private limiter = new RateLimiterMemory({
    points: 100, // Max requests
    duration: 60 * 60, // Per hour
    blockDuration: 900, // 15min block if exceeded
  });

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const ip = req.ip;

    try {
      await this.limiter.consume(ip);
      return true;
    } catch {
      throw new HttpException('Too Many Requests', 429);
    }
  }
}
