import { user_status } from "../enums/user_status.enum";

export class User {
  id: string;
  email: string;
  mobile?: string;
  passwordHash: string;
  firstName: string;
  lastName: string;
  profilePicUrl?: string;
  language: string;
  timeZone: string;
  status: user_status;
  deletedAt: Date;
  twoFactorSecret?: string;
  twoFactorEnabled: boolean;
  lastLoginAt?: Date;
  allowedChannels: string[];
  refreshToken?: string;
  backupCodes?: string[];
  createdAt: Date;
  updatedAt: Date;
}
