import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  UpdateDateColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity('sessions')
export class SessionSchema {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @Column()
  deviceInfo: string;

  @Column({ default: false })
  isRevoked: boolean;

  @Column()
  expiresAt: Date;

  @Column({ nullable: true })
  revokedAt?: Date;

  @Column({ nullable: true })
  revokedReason?: string;

  @Column({ nullable: true })
  tokenId: string;

  @UpdateDateColumn()
  lastActive: Date;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ type: 'json', nullable: true })
  metadata?: Record<string, any>;

  // New fields for refresh token management
  @Column({ nullable: true })
  refreshTokenFamily: string;

  @Column({ default: 1 })
  tokenVersion: number;

  @Column({ nullable: true })
  lastRefreshAt: Date;

  @Column({ default: 0 })
  refreshCount: number;

  @Column({ nullable: true })
  absoluteExpiresAt: Date; // For enforcing maximum refresh token lifetime
}
