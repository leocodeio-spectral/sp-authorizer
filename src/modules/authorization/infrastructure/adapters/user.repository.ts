import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserRepository } from '../../domain/ports/user.repository';
import { User } from '../../domain/models/user.model';
import { UserSchema } from '../entities/user.entity';

@Injectable()
export class TypeOrmUserRepository implements UserRepository {
  constructor(
    @InjectRepository(UserSchema)
    private repository: Repository<UserSchema>,
  ) {}

  async findById(id: string): Promise<User | null> {
    const user = await this.repository.findOne({ where: { id } });
    return user ? this.toDomain(user) : null;
  }

  async findByIdentifier(identifier: string): Promise<User | null> {
    const user = await this.repository.findOne({
      where: [{ email: identifier }, { mobile: identifier }],
    });
    return user ? this.toDomain(user) : null;
  }

  async save(user: Partial<User>): Promise<User> {
    console.log('user creation log 1', user);
    const entity = this.repository.create(user);
    console.log('user creation log 2', entity);
    const savedUser = await this.repository.save(entity);
    console.log('user creation log 3', savedUser);
    return this.toDomain(savedUser);
  }

  async update(id: string, user: Partial<User>): Promise<User> {
    await this.repository.update(id, user);
    const updatedUser = await this.repository.findOne({ where: { id } });
    return this.toDomain(updatedUser);
  }

  private toDomain(schema: UserSchema): User {
    return {
      id: schema.id,
      email: schema.email,
      mobile: schema.mobile,
      passwordHash: schema.passwordHash,
      firstName: schema.firstName,
      lastName: schema.lastName,
      profilePicUrl: schema.profilePicUrl,
      language: schema.language,
      timeZone: schema.timeZone,
      status: schema.status,
      deletedAt: schema.deletedAt,
      twoFactorSecret: schema.twoFactorSecret,
      twoFactorEnabled: schema.twoFactorEnabled,
      lastLoginAt: schema.lastLoginAt,
      allowedChannels: schema.allowedChannels,
      createdAt: schema.createdAt,
      updatedAt: schema.updatedAt,
    };
  }
}
