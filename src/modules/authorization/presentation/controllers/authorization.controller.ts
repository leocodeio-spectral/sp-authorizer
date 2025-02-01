import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  UseGuards,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  HttpException,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiSecurity } from '@nestjs/swagger';
import { Request } from 'express';
import { AuthorizationService } from '../../application/services/authorization.service';
import { JwtAuthGuard } from '../../application/guards/jwt-auth.guard';
import { LocalAuthGuard } from '../../application/guards/local-auth.guard';
import { LoginDto } from '../../application/dtos/login.dto';
import { RegisterDto } from '../../application/dtos/register.dto';
import { IpRateLimitGuard } from '../../application/guards/rate-limit.guard';
import {
  VerifyMobileDto,
  VerifyMobileConfirmDto,
} from '../../application/dtos/verify-mobile.dto';
import { RefreshTokenDto } from '../../application/dtos/refresh-token.dto';
import { ValidateTokenDto } from '../../application/dtos/validate-token.dto';
import { LogoutDto } from '../../application/dtos/logout.dto';
import { UserProfileDto } from '../../application/dtos/user-profile.dto';
import {
  InitiateMobileLoginDto,
  CompleteMobileLoginDto,
} from '../../application/dtos/mobile-login.dto';

@UseGuards(IpRateLimitGuard)
@ApiSecurity('x-api-key')
@Controller('auth')
export class AuthorizationController {
  constructor(private authService: AuthorizationService) {}

  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Setup-2fa' })
  @Post('2fa/setup')
  async setup2FA(@Req() req: Request) {
    return this.authService.setup2FA(req.user.id);
  }

  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Fetch user profile' })
  @Get('me')
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
    type: UserProfileDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or expired token',
  })
  async getProfile(@Req() req: Request): Promise<UserProfileDto> {
    return this.authService.getUserProfile(req.user.id);
  }

  @UseGuards(LocalAuthGuard)
  @ApiOperation({ summary: 'User login' })
  @Post('login')
  async login(@Req() req: Request, @Body() loginDto: LoginDto) {
    return this.authService.login(req.user, loginDto);
  }

  @ApiOperation({ summary: 'User register' })
  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('verify-mobile')
  @ApiOperation({ summary: 'Request mobile OTP' })
  @HttpCode(HttpStatus.OK)
  async requestVerification(@Body() dto: VerifyMobileDto) {
    await this.authService.requestMobileOTP(dto.mobile);
    return {
      statusCode: HttpStatus.OK,
      message: 'Verification code sent',
    };
  }

  @Post('verify-mobile/confirm')
  @ApiOperation({ summary: 'Confirm mobile OTP' })
  @HttpCode(HttpStatus.OK)
  async confirmVerification(@Body() dto: VerifyMobileConfirmDto) {
    const isValid = await this.authService.verifyOTP(dto.mobile, dto.code);
    if (!isValid) {
      throw new UnauthorizedException('Invalid verification code');
    }
    return {
      statusCode: HttpStatus.OK,
      message: 'Mobile number verified successfully',
    };
  }

  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh your access token' })
  @Post('refresh')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshAccessToken(refreshTokenDto.refreshToken);
  }

  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'User logout' })
  @Post('logout')
  async logout(@Body() logoutDto: LogoutDto) {
    await this.authService.logout(logoutDto);
    return {
      statusCode: HttpStatus.OK,
      message: 'Logged out successfully',
    };
  }

  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'User validate' })
  @Post('validate')
  async validateToken(
    @Req() req: Request,
    @Body() validateTokenDto: ValidateTokenDto,
  ) {
    const isValid = await this.authService.validateToken(
      req.user.id,
      validateTokenDto.channel,
      validateTokenDto.clientId,
    );

    return {
      valid: isValid,
      userId: req.user.id,
      channel: validateTokenDto.channel,
    };
  }

  @ApiOperation({ summary: 'Initiate mobile login' })
  @Post('mobile/login')
  @HttpCode(HttpStatus.OK)
  async initiateMobileLogin(@Body() dto: InitiateMobileLoginDto) {
    return this.authService.initiateMobileLogin(dto);
  }

  @ApiOperation({ summary: 'Verify mobile login' })
  @Post('mobile/login/verify')
  @HttpCode(HttpStatus.OK)
  async completeMobileLogin(@Body() dto: CompleteMobileLoginDto) {
    return this.authService.completeMobileLogin(dto);
  }
}
