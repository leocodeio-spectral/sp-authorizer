import { Module } from '@nestjs/common';
import { ValidationController } from './presentation/controllers/validation.controller';
import { ValidationService } from './application/services/validation.service';


@Module({
  imports: [],
  controllers: [ValidationController],
  providers: [ValidationService],
})
export class ValidationModule {}
