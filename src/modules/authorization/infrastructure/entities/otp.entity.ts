import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('otps')
export class OTPSchema {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  mobile: string;

  @Column({ nullable: true })
  code?: string;

  @Column({ nullable: true })
  verificationSid?: string;

  @Column()
  expiresAt: Date;

  @Column({ default: false })
  verified: boolean;

  @Column({ nullable: true })
  reference?: string;

  @Column({ type: 'json', nullable: true })
  metadata?: Record<string, any>;
}
