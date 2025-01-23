import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthorizationModule } from './modules/authorization/authorization.module';
import { ValidationModule } from './modules/validation/validation.module';
import { LoggingModule } from '@leocodeio-njs/njs-logging';
import { HealthModule } from '@leocodeio-njs/njs-health';
import { ApiKeyGuard } from '@leocodeio-njs/njs-auth';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { LoggingInterceptor } from '@leocodeio-njs/njs-logging';
import { AppConfigModule } from '@leocodeio-njs/njs-config';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot(),
    AuthorizationModule,
    ValidationModule,
    AppConfigModule,
    LoggingModule,
    HealthModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggingInterceptor,
    },
    // {
    //   provide: APP_GUARD,
    //   useClass: ApiKeyGuard,
    // },
  ],
})
export class AppModule {}
