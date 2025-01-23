import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthorizationModule } from './modules/authorization/authorization.module';
import { ValidationModule } from './modules/validation/validation.module';

@Module({
  imports: [AuthorizationModule, ValidationModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
