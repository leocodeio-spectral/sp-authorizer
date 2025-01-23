import { Injectable } from '@nestjs/common';

@Injectable()
export class ValidationService {
  constructor() {}

  getHello(): string {
    return 'Hello World!';
  }
}
