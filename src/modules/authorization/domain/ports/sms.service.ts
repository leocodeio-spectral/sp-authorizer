// ports/sms.service.ts
export interface SmsService {
  // sendOTP(mobile: string, otp: string): Promise<void>;
  sendVerification(mobile: string): Promise<{ sid: string }>;
  checkVerification(
    mobile: string,
    code: string,
    verificationSid: string,
  ): Promise<boolean>;
  
}
