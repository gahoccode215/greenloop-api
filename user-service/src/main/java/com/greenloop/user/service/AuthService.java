package com.greenloop.user.service;

import com.greenloop.user.dto.request.*;
import com.greenloop.user.dto.response.AuthResponse;

public interface AuthService {

  AuthResponse login(LoginRequest request);

  void register(RegisterRequest request);

  AuthResponse refreshToken(RefreshTokenRequest request);

  void logout(String accessToken);

  void changePassword(String accessToken, ChangePasswordRequest request);

  void verifyEmailOtp(VerifyEmailRequest request);

  void resendVerificationOtp(String email);

  void resendPasswordResetOtp(String email);

  void forgotPassword(ForgotPasswordRequest request);

  void verifyPasswordResetOtp(VerifyPasswordResetOtpRequest request);

  void resetPassword(ResetPasswordRequest request);
}
