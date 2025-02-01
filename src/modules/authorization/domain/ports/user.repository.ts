import { User } from '../../domain/models/user.model';

export interface UserRepository {
  findById(id: string): Promise<User | null>;
  findByIdentifier(identifier: string): Promise<User | null>;
  save(user: Partial<User>): Promise<User>;
  update(id: string, user: Partial<User>): Promise<User>;
}
