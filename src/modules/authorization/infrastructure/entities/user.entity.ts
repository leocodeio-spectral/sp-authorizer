import { user_status } from 'src/modules/authorization/domain/enums/user_status.enum';
import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('users')
export class UserSchema {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true, unique: true })
  mobile?: string;

  @Column()
  passwordHash: string;

  @Column({ type: 'text', nullable: true })
  firstName: string;

  @Column({ type: 'text', nullable: true })
  lastName: string;

  @Column({ type: 'text', nullable: true })
  profilePicUrl?: string;

  @Column({ type: 'text', default: 'en' })
  language?: string;

  @Column({ type: 'text', default: 'UTC' })
  timeZone?: string;

  @Column({
    type: 'text',
    enum: user_status,
    default: user_status.ACTIVE,
    enumName: 'user_status',
  })
  status?: user_status;

  @Column({ type: 'timestamp with time zone', nullable: true, default: null })
  deletedAt: Date;

  @Column({ nullable: true })
  twoFactorSecret?: string;

  @Column({ default: false })
  twoFactorEnabled: boolean;

  @Column({ nullable: true })
  lastLoginAt?: Date;

  @Column('simple-array')
  allowedChannels: string[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ nullable: true })
  refreshToken?: string;

  @Column('simple-array', { nullable: true })
  backupCodes?: string[];
}
