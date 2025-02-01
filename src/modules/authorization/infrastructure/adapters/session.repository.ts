// auth/infrastructure/persistence/typeorm/session.repository.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { LessThan, MoreThan, Repository } from 'typeorm';
import { SessionRepository } from '../../domain/ports/session.repository';
import { Session } from '../../domain/models/session.model';
import { SessionSchema } from '../entities/session.entity';

@Injectable()
export class TypeOrmSessionRepository implements SessionRepository {
  constructor(
    @InjectRepository(SessionSchema)
    private repository: Repository<SessionSchema>,
  ) {
    // Set up periodic cleanup of expired sessions
    setInterval(() => this.cleanupExpiredSessions(), 1000 * 60 * 60); // Run every hour
  }

  async create(session: Session): Promise<void> {
    const entity = this.repository.create({
      ...session,
      absoluteExpiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      metadata: {
        createdFrom: session.deviceInfo,
        userAgent: session.deviceInfo,
      },
    });
    await this.repository.save(entity);
  }

  async findSessionById(sessionId: string): Promise<Session | null> {
    const session = await this.repository.findOne({
      where: { id: sessionId },
    });

    return session ? this.toDomain(session) : null;
  }

  async invalidate(
    sessionId: string,
    reason: string = 'User logout',
  ): Promise<void> {
    const now = new Date();
    await this.repository.update(sessionId, {
      isRevoked: true,
      revokedAt: now,
      revokedReason: reason,
      lastActive: now,
    });
  }

  async invalidateAllUserSessions(
    userId: string,
    reason: string = 'Security measure',
  ): Promise<void> {
    const now = new Date();
    await this.repository.update(
      { userId, isRevoked: false },
      {
        isRevoked: true,
        revokedAt: now,
        revokedReason: reason,
        lastActive: now,
      },
    );
  }

  async findByRefreshTokenFamily(family: string): Promise<Session | null> {
    const session = await this.repository.findOne({
      where: { refreshTokenFamily: family },
    });
    return session ? this.toDomain(session) : null;
  }

  async isValid(sessionId: string): Promise<boolean> {
    const session = await this.repository.findOne({
      where: {
        id: sessionId,
        isRevoked: false,
        expiresAt: MoreThan(new Date()),
        absoluteExpiresAt: MoreThan(new Date()),
      },
    });

    if (session) {
      // Update last active timestamp
      await this.updateLastActive(sessionId);
      return true;
    }

    return false;
  }

  async updateLastActive(sessionId: string): Promise<void> {
    await this.repository.update(sessionId, {
      lastActive: new Date(),
    });
  }

  async cleanupExpiredSessions(): Promise<void> {
    const now = new Date();
    await this.repository.update(
      {
        isRevoked: false,
        expiresAt: LessThan(now),
      },
      {
        isRevoked: true,
        revokedAt: now,
        revokedReason: 'Session expired',
      },
    );

    // Also cleanup absolutely expired sessions
    await this.repository.update(
      {
        isRevoked: false,
        absoluteExpiresAt: LessThan(now),
      },
      {
        isRevoked: true,
        revokedAt: now,
        revokedReason: 'Maximum session lifetime exceeded',
      },
    );
  }

  async update(sessionId: string, updates: Partial<Session>): Promise<void> {
    await this.repository.update(sessionId, {
      ...updates,
      lastActive: new Date(),
    });
  }

  async getUserActiveSessions(userId: string): Promise<Session[]> {
    const sessions = await this.repository.find({
      where: {
        userId,
        isRevoked: false,
        expiresAt: MoreThan(new Date()),
        absoluteExpiresAt: MoreThan(new Date()),
      },
      order: {
        lastActive: 'DESC', // Most recent first
      },
    });

    return sessions.map((s) => this.toDomain(s));
  }

  private toDomain(schema: SessionSchema): Session {
    return {
      id: schema.id,
      userId: schema.userId,
      deviceInfo: schema.deviceInfo,
      lastActive: schema.lastActive,
      expiresAt: schema.expiresAt,
      isRevoked: schema.isRevoked,
      revokedAt: schema.revokedAt,
      revokedReason: schema.revokedReason,
      createdAt: schema.createdAt,
      metadata: schema.metadata,
      refreshTokenFamily: schema.refreshTokenFamily,
      tokenVersion: schema.tokenVersion,
      lastRefreshAt: schema.lastRefreshAt,
      refreshCount: schema.refreshCount,
      absoluteExpiresAt: schema.absoluteExpiresAt,
    };
  }
}
