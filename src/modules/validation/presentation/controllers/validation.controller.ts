import { Controller, Get } from '@nestjs/common';
import { ValidationService } from '../../application/services/validation.service';

@Controller('validation')
export class ValidationController {
  constructor(private readonly validationService: ValidationService) {}

  @Get()
  getHello(): string {
    return this.validationService.getHello();
  }
}
