import { Module } from '@nestjs/common';
import { AuthorizationController } from './presentation/controllers/authorization.controller';
import { AuthorizationService } from './application/services/authorization.service';

@Module({
  imports: [],
  controllers: [AuthorizationController],
  providers: [AuthorizationService],
})
export class AuthorizationModule {}
