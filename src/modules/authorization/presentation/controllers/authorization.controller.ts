import { Controller, Get } from '@nestjs/common';
import { AuthorizationService } from '../../application/services/authorization.service';

@Controller('authorization')
export class AuthorizationController {
  constructor(private readonly authorizationService: AuthorizationService) {}

  @Get()
  getHello(): string {
    return this.authorizationService.getHello();
  }
}
