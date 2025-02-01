import { Provider } from '@nestjs/common';
import { Session } from '../../domain/models/session.model';

export interface SessionRepository {
  create(session: Session): Promise<void>;
  invalidate(sessionId: string, reason: string): Promise<void>;
  invalidateAllUserSessions(userId: string, reason: string): Promise<void>;
  isValid(sessionId: string): Promise<boolean>;
  findSessionById(sessionId: string): Promise<Session | null>;
  cleanupExpiredSessions(): Promise<void>;
  getUserActiveSessions(userId: string): Promise<Session[]>;
  update(sessionId: string, updates: Partial<Session>): Promise<void>;
}