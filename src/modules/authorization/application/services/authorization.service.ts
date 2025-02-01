import {
  Injectable,
  Inject,
  UnauthorizedException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { authenticator } from 'otplib';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { UserRepository } from '../../domain/ports/user.repository';
import { USER_REPOSITORY } from '../constants';
import { TokenPayload } from '../types/token';
import { User } from '../../domain/models/user.model';
import { SmsService } from '../../domain/ports/sms.service';
import { OTPRepository } from '../../infrastructure/adapters/otp.repository';
import { RegisterDto } from '../dtos/register.dto';
import { Session } from '../../domain/models/session.model';
import { DeviceInfoDto, LoginDto } from '../dtos/login.dto';
import { LogoutDto } from '../dtos/logout.dto';
import { UserProfileDto } from '../dtos/user-profile.dto';
import { SessionRepository } from '../../domain/ports/session.repository';
import { ConfigService } from '@nestjs/config';
import {
  CompleteMobileLoginDto,
  InitiateMobileLoginDto,
} from '../dtos/mobile-login.dto';
import { user_status } from 'src/auth/domain/enums/user_status.enum';
import { LoggerService } from '@netlabs-australia-pty-ltd/netlabs-njs-common';
import { DebugUtil } from '@netlabs-australia-pty-ltd/netlabs-njs-common';
import { CorrelationService } from '@netlabs-australia-pty-ltd/netlabs-njs-common';

interface RefreshTokenPayload {
  sub: string;
  tokenFamily: string;
  sessionId: string;
  version: number;
  jti: string;
}

@Injectable()
export class AuthorizationService {
  private rateLimiter: RateLimiterMemory;
  private refreshTokenLimiter: RateLimiterMemory;

  constructor(
    @Inject(USER_REPOSITORY) private userRepository: UserRepository,
    @Inject('SMS_SERVICE') private smsService: SmsService,
    @Inject('OTP_REPOSITORY') private otpRepository: OTPRepository,
    @Inject('SESSION_REPOSITORY') private sessionRepository: SessionRepository,
    private configService: ConfigService,
    private jwtService: JwtService,
    private readonly logger: LoggerService,
    private readonly debugUtil: DebugUtil,
    private readonly correlationService: CorrelationService,
  ) {
    this.logger.setLogContext('AuthService');

    // Initialize rate limiter for login attempts
    this.rateLimiter = new RateLimiterMemory({
      points: 5, // 5 login attempts
      duration: 60 * 15, // per 15 minutes
      blockDuration: 60 * 60, // Block for 1 hour
    });
    // Add rate limiter for refresh token endpoint
    this.refreshTokenLimiter = new RateLimiterMemory({
      points: 5, // 5 attempts
      duration: 60, // per 1 minute
      blockDuration: 300, // Block for 5 minutes
    });

    this.logger.debug('Initialized rate limiters');
  }

  async register(dto: RegisterDto): Promise<User> {
    // Verify mobile OTP only for mobile channel
    if (dto.channel === 'mobile') {
      const isValidOTP = await this.otpRepository.verify(
        dto.mobile,
        dto.mobileVerificationCode,
      );
      if (!isValidOTP) {
        throw new UnauthorizedException('Invalid mobile verification code');
      }
    }

    const passwordHash = await this.hashPassword(dto.password);

    const user = await this.userRepository.save({
      email: dto.email,
      mobile: dto.mobile,
      firstName: dto.firstName,
      lastName: dto.lastName,
      profilePicUrl: dto.profilePicUrl,
      language: dto.language,
      timeZone: dto.timeZone,
      passwordHash,
      allowedChannels: [dto.channel],
      twoFactorEnabled: false,
    });

    return user;
  }

  async validateUser(identifier: string, password: string): Promise<any> {
    this.logger.debug('Validating user', {
      identifier,
      correlationId: this.correlationService.getCorrelationId(),
    });

    await this.rateLimiter.consume(identifier);

    const user = await this.userRepository.findByIdentifier(identifier);
    if (!user) {
      this.logger.warn('User not found during validation', {
        identifier,
        correlationId: this.correlationService.getCorrelationId(),
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      this.logger.warn('Invalid password provided', {
        identifier,
        correlationId: this.correlationService.getCorrelationId(),
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    this.logger.debug('User validated successfully', {
      identifier,
      correlationId: this.correlationService.getCorrelationId(),
    });

    const { passwordHash, ...result } = user;
    return result;
  }

  async login(user: any, loginDto: LoginDto) {
    this.logger.debug('Processing login request', {
      userId: user.id,
      channel: loginDto.channel,
    });

    if (!user.allowedChannels.includes(loginDto.channel)) {
      this.logger.warn('Unauthorized channel access attempt', {
        userId: user.id,
        channel: loginDto.channel,
      });
      throw new UnauthorizedException('Channel not authorized');
    }

    // Handle 2FA
    if (user.twoFactorEnabled) {
      if (!loginDto.twoFactorCode) {
        this.logger.debug('2FA required for user', { userId: user.id });
        return { requiresTwoFactor: true };
      }

      await this.rateLimiter.consume(`2fa_${user.id}`);
      const isValidToken = authenticator.verify({
        token: loginDto.twoFactorCode,
        secret: user.twoFactorSecret,
      });

      if (!isValidToken) {
        this.logger.warn('Invalid 2FA code provided', { userId: user.id });
        throw new UnauthorizedException('Invalid 2FA code');
      }
    }

    const deviceInfo = this.getDeviceInfo(loginDto);
    const sessionId = crypto.randomUUID();
    const tokenFamily = crypto.randomUUID();

    this.debugUtil.debug(this.logger, 'Generating tokens for user', {
      userId: user.id,
      sessionId,
      deviceInfo,
    });

    // Generate tokens
    const [accessToken, refreshToken] = await Promise.all([
      this.generateAccessToken(user, sessionId, loginDto.channel),
      this.generateRefreshToken(user.id, sessionId, tokenFamily),
    ]);

    // Create session with new fields
    await this.sessionRepository.create({
      id: sessionId,
      userId: user.id,
      deviceInfo,
      lastActive: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      isRevoked: false,
      refreshTokenFamily: tokenFamily,
      tokenVersion: 1,
      refreshCount: 0,
      metadata: {
        userAgent: loginDto.userAgent,
        channel: loginDto.channel,
        lastTokenRefresh: new Date(),
      },
    });

    this.logger.debug('Login successful', {
      userId: user.id,
      sessionId,
      channel: loginDto.channel,
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      sessionId,
      requiresTwoFactor: false,
    };
  }

  private async generateAccessToken(
    user: any,
    sessionId: string,
    channel: string,
  ): Promise<string> {
    const payload: TokenPayload = {
      sub: user.id,
      email: user.email,
      channel: channel,
      sessionId: sessionId, // Use the provided sessionId
    };
    return this.jwtService.sign(payload);
  }

  async logout(logoutDto: LogoutDto): Promise<void> {
    try {
      // Verify and decode the access token
      const decoded = this.jwtService.verify<TokenPayload>(
        logoutDto.accessToken,
        {
          secret: this.configService.get('JWT_SECRET'),
        },
      );

      if (!decoded.sub || !decoded.sessionId) {
        throw new UnauthorizedException('Invalid token');
      }

      // First verify the session exists and belongs to the user
      const session = await this.sessionRepository.findSessionById(
        decoded.sessionId,
      );
      if (!session || session.userId !== decoded.sub) {
        throw new UnauthorizedException('Invalid session');
      }

      // Invalidate the session
      await this.sessionRepository.invalidate(
        decoded.sessionId,
        'User initiated logout',
      );

      // Update user's refresh token
      await this.userRepository.update(decoded.sub, {
        refreshToken: null,
      });
    } catch (error) {
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid token');
      }
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Token has expired');
      }
      throw error;
    }
  }

  private async generateRefreshToken(
    userId: string,
    sessionId: string,
    tokenFamily: string,
    version: number = 1,
  ): Promise<string> {
    const payload: RefreshTokenPayload = {
      sub: userId,
      tokenFamily,
      sessionId,
      version,
      jti: crypto.randomUUID(),
    };

    return this.jwtService.sign(payload, {
      expiresIn: '7d',
      secret:
        this.configService.get('JWT_REFRESH_SECRET') ||
        this.configService.get('JWT_SECRET'),
    });
  }

  async refreshAccessToken(refreshToken: string): Promise<{
    access_token: string;
    refresh_token: string;
    sessionId: string;
  }> {
    try {
      // Apply rate limiting
      const tokenId = this.jwtService.decode(refreshToken)['jti'];
      await this.refreshTokenLimiter.consume(tokenId);

      // Verify the refresh token
      const decoded = this.jwtService.verify<RefreshTokenPayload>(
        refreshToken,
        {
          secret:
            this.configService.get('JWT_REFRESH_SECRET') ||
            this.configService.get('JWT_SECRET'),
        },
      );

      // Get and validate session
      const session = await this.sessionRepository.findSessionById(
        decoded.sessionId,
      );
      if (!session || session.isRevoked) {
        throw new UnauthorizedException('Invalid session');
      }

      // Verify token family and version
      if (
        session.refreshTokenFamily !== decoded.tokenFamily ||
        session.tokenVersion !== decoded.version
      ) {
        // Potential token reuse - revoke all user sessions
        await this.sessionRepository.invalidateAllUserSessions(
          decoded.sub,
          'Token reuse detected',
        );
        throw new UnauthorizedException('Security violation detected');
      }

      // Check if session has exceeded maximum refresh count
      if (session.refreshCount >= 1000) {
        // Arbitrary limit
        await this.sessionRepository.invalidate(
          session.id,
          'Maximum refresh count exceeded',
        );
        throw new UnauthorizedException('Session expired');
      }

      // Get user
      const user = await this.userRepository.findById(decoded.sub);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Generate new tokens
      const newAccessToken = await this.generateAccessToken(
        user,
        session.id,
        session.metadata?.channel || 'web',
      );

      // Rotate refresh token
      const newRefreshToken = await this.generateRefreshToken(
        user.id,
        session.id,
        decoded.tokenFamily,
        decoded.version + 1,
      );

      // Update session
      await this.sessionRepository.update(session.id, {
        tokenVersion: decoded.version + 1,
        lastRefreshAt: new Date(),
        refreshCount: (session.refreshCount || 0) + 1,
        metadata: {
          ...session.metadata,
          lastTokenRefresh: new Date(),
        },
      });

      return {
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
        sessionId: session.id,
      };
    } catch (error) {
      if (error.name === 'RateLimiterError') {
        throw new HttpException(
          'Too many refresh attempts',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid token format');
      }
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Refresh token expired');
      }
      throw error;
    }
  }

  async setup2FA(
    userId: string,
  ): Promise<{ secret: string; qrCode: string; backupCodes: string[] }> {
    const secret = authenticator.generateSecret();
    const qrCode = authenticator.keyuri(userId, 'Your App', secret);
    const backupCodes = await this.generateBackupCodes();

    await this.userRepository.update(userId, {
      twoFactorSecret: secret,
      twoFactorEnabled: true,
      backupCodes: await Promise.all(
        backupCodes.map((code) => bcrypt.hash(code, 10)),
      ),
    });

    return { secret, qrCode, backupCodes };
  }

  async validateToken(
    userId: string,
    channel: string,
    clientId?: string,
  ): Promise<boolean> {
    const user = await this.userRepository.findById(userId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.allowedChannels.includes(channel) && channel != 'api') {
      throw new UnauthorizedException('Channel not authorized');
    }

    // For API clients, verify client ID if provided
    if (channel === 'api' && clientId) {
      const isValidClient = await this.verifyApiClient(clientId, userId);
      if (!isValidClient) {
        throw new UnauthorizedException('Invalid API client');
      }
    }

    return true;
  }

  private async verifyApiClient(
    clientId: string,
    userId: string,
  ): Promise<boolean> {
    this.logger.debug('Verifying API client', {
      clientId,
      userId,
      correlationId: this.correlationService.getCorrelationId(),
    });

    // TODO: Implement API client verification
    const validClients = ['validMicroservice'];
    return validClients.includes(clientId);
  }

  private async generateBackupCodes(): Promise<string[]> {
    const codes = [];
    for (let i = 0; i < 10; i++) {
      codes.push(Math.random().toString(36).slice(-8));
    }
    return codes;
  }

  private async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }

  async requestMobileOTP(mobile: string): Promise<void> {
    this.logger.debug('Starting mobile OTP request', {
      mobile,
      correlationId: this.correlationService.getCorrelationId(),
    });

    await this.rateLimiter.consume(mobile);
    const testNumbers =
      this.configService.get('TEST_PHONE_NUMBERS')?.split(',') || [];

    this.debugUtil.debug(this.logger, 'Test numbers configuration', {
      testNumbers,
      correlationId: this.correlationService.getCorrelationId(),
    });

    if (!testNumbers.includes(mobile)) {
      this.logger.debug('Production number detected, using Twilio', {
        mobile,
        correlationId: this.correlationService.getCorrelationId(),
      });

      try {
        const twilioVerificationResponse =
          await this.smsService.sendVerification(mobile);

        this.debugUtil.debug(
          this.logger,
          'Twilio verification response received',
          {
            mobile,
            sid: twilioVerificationResponse.sid,
            correlationId: this.correlationService.getCorrelationId(),
          },
        );

        const otp = await this.otpRepository.save({
          mobile,
          verificationSid: twilioVerificationResponse.sid,
          expiresAt: new Date(Date.now() + 10 * 60 * 1000),
          verified: false,
        });

        this.logger.debug('OTP saved successfully', {
          mobile,
          correlationId: this.correlationService.getCorrelationId(),
        });
      } catch (error) {
        this.logger.error('Failed to send verification code', error, {
          mobile,
          correlationId: this.correlationService.getCorrelationId(),
        });
        throw new Error('Failed to send verification code');
      }
    } else {
      this.logger.debug('Test number detected, generating local OTP', {
        mobile,
        correlationId: this.correlationService.getCorrelationId(),
      });

      const code = this.generateOTP();
      try {
        const otp = await this.otpRepository.save({
          mobile,
          code,
          expiresAt: new Date(Date.now() + 10 * 60 * 1000),
          verified: false,
        });

        this.logger.debug('Test OTP saved successfully', {
          mobile,
          code, // Only logging code in test mode
          correlationId: this.correlationService.getCorrelationId(),
        });
      } catch (error) {
        this.logger.error('Failed to save test OTP', error, {
          mobile,
          correlationId: this.correlationService.getCorrelationId(),
        });
        throw error;
      }
    }
  }

  private generateOTP(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  async verifyOTP(mobile: string, code: string): Promise<boolean> {
    const testNumbers =
      this.configService.get('TEST_PHONE_NUMBERS')?.split(',') || [];

    if (!testNumbers.includes(mobile)) {
      // For production numbers, verify through Twilio
      const storedOTP = await this.otpRepository.findPendingOTP(mobile);

      if (!storedOTP) return false;

      const isValid = await this.smsService.checkVerification(
        mobile,
        code,
        storedOTP.verificationSid,
      );
      if (isValid) {
        await this.otpRepository.markAsVerified(storedOTP.id);
        return true;
      }
      return false;
    } else {
      // For test numbers, verify against our stored OTP
      return this.otpRepository.verify(mobile, code);
    }
  }

  private getDeviceInfo(dto: DeviceInfoDto): string {
    return `${dto.channel}${dto.userAgent ? ` - ${dto.userAgent}` : ''}`;
  }
  async getUserSessions(accessToken: string): Promise<Session[]> {
    try {
      // Verify and decode the access token
      const decoded = this.jwtService.verify<TokenPayload>(accessToken, {
        secret: this.configService.get('JWT_SECRET'),
      });

      if (!decoded.sub) {
        throw new UnauthorizedException('Invalid token');
      }

      // Get only the sessions for this specific user
      return this.sessionRepository.getUserActiveSessions(decoded.sub);
    } catch (error) {
      if (
        error.name === 'JsonWebTokenError' ||
        error.name === 'TokenExpiredError'
      ) {
        throw new UnauthorizedException('Invalid or expired token');
      }
      throw error;
    }
  }

  async getUserProfile(userId: string): Promise<UserProfileDto> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return {
      id: user.id,
      email: user.email,
      mobile: user.mobile,
      twoFactorEnabled: user.twoFactorEnabled,
      allowedChannels: user.allowedChannels,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
    };
  }

  async initiateMobileLogin(
    dto: InitiateMobileLoginDto,
  ): Promise<{ reference: string }> {
    // Rate limit check
    await this.rateLimiter.consume(dto.mobile);

    // Verify user is properly registered
    await this.validateRegisteredUser(dto.mobile);

    // Generate and send OTP
    await this.requestMobileOTP(dto.mobile);

    // Create temporary login reference
    const reference = crypto.randomUUID();
    await this.otpRepository.save({
      mobile: dto.mobile,
      reference,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      verified: false,
      metadata: {
        loginAttempt: true,
        channel: dto.channel,
        userAgent: dto.userAgent,
      },
    });

    return { reference };
  }

  async completeMobileLogin(dto: CompleteMobileLoginDto): Promise<{
    access_token: string;
    refresh_token: string;
    sessionId: string;
  }> {
    // Verify user is registered first
    const user = await this.validateRegisteredUser(dto.mobile);

    // Verify OTP
    const otpRecord = await this.otpRepository.findPendingOTP(dto.mobile);
    if (!otpRecord || !otpRecord.reference) {
      throw new UnauthorizedException('Invalid login attempt');
    }

    const isValid = await this.verifyOTP(dto.mobile, dto.otp);
    if (!isValid) {
      throw new UnauthorizedException('Invalid OTP');
    }

    // Create session and tokens
    const sessionId = crypto.randomUUID();
    const tokenFamily = crypto.randomUUID();

    const [accessToken, refreshToken] = await Promise.all([
      this.generateAccessToken(user, sessionId, dto.channel),
      this.generateRefreshToken(user.id, sessionId, tokenFamily),
    ]);

    // Create session
    await this.sessionRepository.create({
      id: sessionId,
      userId: user.id,
      deviceInfo: this.getDeviceInfo(dto),
      lastActive: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      isRevoked: false,
      refreshTokenFamily: tokenFamily,
      tokenVersion: 1,
      refreshCount: 0,
      metadata: {
        userAgent: dto.userAgent,
        channel: dto.channel,
        lastTokenRefresh: new Date(),
        loginMethod: 'mobile_otp',
      },
    });

    // Update user's last login
    await this.userRepository.update(user.id, {
      lastLoginAt: new Date(),
    });

    // Cleanup OTP
    await this.otpRepository.delete(otpRecord.id);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      sessionId,
    };
  }

  private async validateRegisteredUser(mobile: string): Promise<User> {
    const user = await this.userRepository.findByIdentifier(mobile);

    if (!user) {
      throw new UnauthorizedException(
        'Please register before attempting to login. Registration requires both email and mobile number.',
      );
    }

    // Ensure user has completed registration (has both email and mobile)
    if (!user.email || !user.mobile) {
      throw new UnauthorizedException(
        'Incomplete registration. Please complete registration with both email and mobile number.',
      );
    }

    return user;
  }

  async isUserExists(
    type: 'email' | 'mobile',
    identifier: string,
  ): Promise<boolean> {
    const user = await this.userRepository.findByIdentifier(identifier);
    if (!user) {
      return false;
    }
    return true;
  }
}
