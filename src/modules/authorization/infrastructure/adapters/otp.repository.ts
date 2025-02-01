import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
import { OTPSchema } from '../entities/otp.entity';
import { OTP } from '../../domain/models/otp.model';

export interface OTPRepository {
  save(otp: Partial<OTP>): Promise<OTP>;
  verify(mobile: string, code: string): Promise<boolean>;
  findPendingOTP(mobile: string): Promise<OTP | null>;
  markAsVerified(id: string): Promise<void>;
  delete(id: string): Promise<void>;
  findByReference(reference: string): Promise<OTP | null>;
  deleteByReference(reference: string): Promise<void>;
}

@Injectable()
export class TypeOrmOTPRepository implements OTPRepository {
  constructor(
    @InjectRepository(OTPSchema)
    private repository: Repository<OTPSchema>,
  ) {}

  async save(otp: Partial<OTP>): Promise<OTP> {
    console.log('Saving OTP:', otp);
    try {
      const entity = this.repository.create(otp);
      const savedOTP = await this.repository.save(entity);
      console.log('OTP saved successfully:', savedOTP);
      return savedOTP;
    } catch (error) {
      console.error('Error saving OTP:', error);
      throw error;
    }
  }

  async verify(mobile: string, code: string): Promise<boolean> {
    const otp = await this.repository.findOne({
      where: {
        mobile,
        code,
        verified: false,
        expiresAt: MoreThan(new Date()),
      },
    });

    console.log('Found OTP:', otp);

    if (!otp) return false;

    otp.verified = true;
    await this.repository.save(otp);
    return true;
  }

  async findPendingOTP(mobile: string): Promise<OTP | null> {
    console.log(`Finding pending OTP for mobile: ${mobile}`);
    try {
      const otp = await this.repository.findOne({
        where: {
          mobile,
          verified: false,
          expiresAt: MoreThan(new Date()),
        },
        order: { expiresAt: 'DESC' },
      });
      console.log(`Pending OTP result:`, otp);
      return otp;
    } catch (error) {
      console.error('Error finding pending OTP:', error);
      throw error;
    }
  }

  async markAsVerified(id: string): Promise<void> {
    await this.repository.update(id, { verified: true });
  }

  async delete(id: string): Promise<void> {
    await this.repository.delete(id);
  }
  
  async findByReference(reference: string): Promise<OTP | null> {
    return this.repository.findOne({
      where: {
        reference,
        verified: false,
        expiresAt: MoreThan(new Date()),
      },
    });
  }

  async deleteByReference(reference: string): Promise<void> {
    await this.repository.delete({ reference });
  }
}
