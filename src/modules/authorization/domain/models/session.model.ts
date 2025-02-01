export class Session {
  id: string;
  userId: string;
  deviceInfo: string;
  lastActive: Date;
  expiresAt: Date;
  isRevoked: boolean;
  revokedAt?: Date;
  revokedReason?: string;
  createdAt?: Date;
  metadata?: Record<string, any>;
  refreshTokenFamily?: string;
  tokenVersion: number;
  lastRefreshAt?: Date;
  refreshCount: number;
  absoluteExpiresAt?: Date;
}
