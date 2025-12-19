package com.greenloop.user.service.impl;

import com.greenloop.user.constant.ProviderConstants;
import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.dto.event.PasswordResetEvent;
import com.greenloop.user.dto.event.UserRegistrationEvent;
import com.greenloop.user.dto.request.*;
import com.greenloop.user.dto.response.AuthResponse;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.exception.*;
import com.greenloop.user.repository.RoleRepository;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.AuthService;
import com.greenloop.user.service.CacheService;
import com.greenloop.user.util.JwtUtil;
import com.greenloop.user.util.OtpUtil;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

  private final UserRepository userRepository;
  private final RoleRepository roleRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtUtil jwtUtil;
  private final OtpUtil otpUtil;
  private final StreamBridge streamBridge;
  private final CacheService cacheService;

  @Value("${app.otp.expiry-in-minutes}")
  private long otpExpiryMinutes;

  @Value("${app.otp.redis.email-verify-prefix}")
  private String emailVerifyPrefix;

  @Value("${app.otp.redis.password-reset-prefix}")
  private String passwordResetPrefix;

  @Override
  public AuthResponse login(LoginRequest request) {
    User user = userRepository.findByEmail(request.getEmail()).orElseThrow(LoginException::new);
    if (!user.getIsEmailVerified() || !user.isActive()) {
      throw new AccountNotActiveException();
    }
    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
      throw new LoginException();
    }
    String accessToken = jwtUtil.generateToken(user);
    String refreshToken = jwtUtil.generateRefreshToken(user);
    List<String> roleNames = user.getRoles().stream().map(Role::getName).toList();
    user.setLastLoginAt(LocalDateTime.now());
    userRepository.save(user);
    return AuthResponse.builder()
        .accessToken(accessToken)
        .refreshToken(refreshToken)
        .type("Bearer")
        .userId(user.getId())
        .fullName(user.getFullName())
        .email(user.getEmail())
        .roles(roleNames)
        .expiresIn(jwtUtil.getExpirationTime())
        .refreshExpiresIn(jwtUtil.getRefreshExpirationTime())
        .build();
  }

  @Transactional
  @Override
  public void register(RegisterRequest request) {
    if (!request.getPassword().equals(request.getConfirmPassword())) {
      throw new RegisterException("Mật khẩu xác nhận không khớp");
    }
    if (userRepository.existsByPhone(request.getPhoneNumber())) {
      throw new PhoneNumberAlreadyExistsException(request.getPhoneNumber());
    }
    User existingUser = userRepository.findByEmail(request.getEmail()).orElse(null);
    String emailVerificationOtp = otpUtil.generateOtp();
    if (existingUser != null) {
      if (existingUser.getIsEmailVerified()) {
        throw new EmailAlreadyExistsException();
      }
      storeEmailVerificationOtp(existingUser.getEmail(), emailVerificationOtp);
      UserRegistrationEvent event =
          UserRegistrationEvent.builder()
              .email(existingUser.getEmail())
              .otpCode(emailVerificationOtp)
              .otpExpiryTime(otpUtil.getOtpExpiryTime())
              .build();
      streamBridge.send("userRegistration-out-0", event);
      return;
    }
    Role userRole =
        roleRepository
            .findByName(RoleConstants.CUSTOMER)
            .orElseThrow(() -> new RoleNotFoundException(RoleConstants.CUSTOMER));
    User newUser =
        User.builder()
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .fullName(request.getFullName())
            .dateOfBirth(request.getDateOfBirth())
            .phone(request.getPhoneNumber())
            .roles(List.of(userRole))
            .isEmailVerified(false)
            .provider(ProviderConstants.LOCAL)
            .build();
    userRepository.save(newUser);
    storeEmailVerificationOtp(newUser.getEmail(), emailVerificationOtp);
    UserRegistrationEvent event =
        UserRegistrationEvent.builder()
            .email(newUser.getEmail())
            .otpCode(emailVerificationOtp)
            .otpExpiryTime(otpUtil.getOtpExpiryTime())
            .build();
    streamBridge.send("userRegistration-out-0", event);
  }

  @Override
  public AuthResponse refreshToken(RefreshTokenRequest request) {
    if (!jwtUtil.validateToken(request.getRefreshToken())
        || !jwtUtil.isRefreshToken(request.getRefreshToken())) {
      throw new InvalidCredentialsException();
    }
    String email = jwtUtil.extractUsername(request.getRefreshToken());
    User user = userRepository.findByEmail(email).orElseThrow(InvalidCredentialsException::new);
    if (!user.isActive()) {
      throw new AccountNotActiveException();
    }
    String newAccessToken = jwtUtil.generateToken(user);
    String newRefreshToken = jwtUtil.generateRefreshToken(user);
    return AuthResponse.builder()
        .accessToken(newAccessToken)
        .refreshToken(newRefreshToken)
        .type("Bearer")
        .expiresIn(jwtUtil.getExpirationTime())
        .refreshExpiresIn(jwtUtil.getRefreshExpirationTime())
        .build();
  }

  @Override
  @Transactional
  public void logout(String accessToken) {
    if (accessToken == null || !jwtUtil.validateToken(accessToken)) {
      throw new InvalidCredentialsException();
    }
    jwtUtil.blacklistToken(accessToken);
  }

  @Override
  @Transactional
  public void changePassword(String accessToken, ChangePasswordRequest request) {
    String email = jwtUtil.extractUsername(accessToken);
    if (!request.getNewPassword().equals(request.getConfirmPassword())) {
      throw new ChangePasswordException("Mật khẩu xác nhận không khớp");
    }
    User user =
        userRepository
            .findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User không tồn tại " + email));
    if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
      throw new ChangePasswordException("Mật khẩu hiện tại không đúng");
    }
    if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
      throw new ChangePasswordException("Mật khẩu mới phải khác mật khẩu hiện tại");
    }
    user.setPassword(passwordEncoder.encode(request.getNewPassword()));
    userRepository.save(user);
  }

  @Override
  @Transactional
  public void verifyEmailOtp(VerifyEmailRequest request) {
    User user =
        userRepository
            .findByEmail(request.getEmail())
            .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));
    if (user.getIsEmailVerified()) {
      throw new VerifyEmailException("Email đã được xác thực", "EMAIL_ALREADY_VERIFIED");
    }
    if (!isEmailVerificationOtpValid(request.getEmail(), request.getOtp())) {
      throw new VerifyEmailException("Mã OTP không đúng hoặc đã hết hạn", "INVALID_OTP");
    }
    user.setIsEmailVerified(true);
    user.setActive(true);
    userRepository.save(user);
    deleteEmailVerificationOtp(request.getEmail());
  }

  @Override
  @Transactional
  public void resendVerificationOtp(String email) {
    User user =
        userRepository.findByEmail(email).orElseThrow(() -> new EmailNotFoundException(email));
    if (user.getIsEmailVerified()) {
      throw new VerifyEmailException("Email đã được xác thực", "EMAIL_ALREADY_VERIFIED");
    }
    String newOtp = otpUtil.generateOtp();
    storeEmailVerificationOtp(email, newOtp);
    UserRegistrationEvent event =
        UserRegistrationEvent.builder()
            .email(user.getEmail())
            .otpCode(newOtp)
            .otpExpiryTime(otpUtil.getOtpExpiryTime())
            .build();
    streamBridge.send("userRegistration-out-0", event);
  }

  @Override
  @Transactional
  public void resendPasswordResetOtp(String email) {
    User user =
        userRepository.findByEmail(email).orElseThrow(() -> new EmailNotFoundException(email));
    if (!user.isActive()) {
      throw new AccountNotActiveException();
    }
    if (getPasswordResetOtp(email) == null) {
      throw new PasswordResetException(
          "Không có yêu cầu đặt lại mật khẩu trước đó", "NO_RESET_REQUEST");
    }
    String newPasswordResetOtp = otpUtil.generateOtp();
    storePasswordResetOtp(email, newPasswordResetOtp);
    PasswordResetEvent event =
        PasswordResetEvent.builder()
            .email(user.getEmail())
            .otpCode(newPasswordResetOtp)
            .otpExpiryTime(otpUtil.getOtpExpiryTime())
            .build();
    streamBridge.send("passwordReset-out-0", event);
  }

  @Override
  @Transactional
  public void forgotPassword(ForgotPasswordRequest request) {
    User user =
        userRepository
            .findByEmail(request.getEmail())
            .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));
    if (!user.isActive()) {
      throw new AccountNotActiveException();
    }
    String passwordResetOtp = otpUtil.generateOtp();
    storePasswordResetOtp(user.getEmail(), passwordResetOtp);
    PasswordResetEvent event =
        PasswordResetEvent.builder()
            .email(user.getEmail())
            .otpCode(passwordResetOtp)
            .otpExpiryTime(otpUtil.getOtpExpiryTime())
            .build();
    streamBridge.send("passwordReset-out-0", event);
  }

  @Override
  @Transactional
  public void verifyPasswordResetOtp(VerifyPasswordResetOtpRequest request) {
    User user =
        userRepository
            .findByEmail(request.getEmail())
            .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));
    if (!isPasswordResetOtpValid(request.getEmail(), request.getOtp())) {
      throw new PasswordResetException("Mã OTP không đúng hoặc đã hết hạn", "INVALID_OTP");
    }
  }

  @Override
  @Transactional
  public void resetPassword(ResetPasswordRequest request) {
    if (!request.getNewPassword().equals(request.getConfirmPassword())) {
      throw new ChangePasswordException("Mật khẩu xác nhận không khớp");
    }
    User user =
        userRepository
            .findByEmail(request.getEmail())
            .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));
    user.setPassword(passwordEncoder.encode(request.getNewPassword()));
    userRepository.save(user);
    deletePasswordResetOtp(request.getEmail());
  }

  private void storeEmailVerificationOtp(String email, String otp) {
    String key = emailVerifyPrefix + email;
    cacheService.set(key, otp, otpExpiryMinutes, TimeUnit.MINUTES);
  }

  private boolean isEmailVerificationOtpValid(String email, String inputOtp) {
    String key = emailVerifyPrefix + email;
    String storedOtp = cacheService.get(key, String.class);
    return storedOtp != null && storedOtp.equals(inputOtp);
  }

  private void deleteEmailVerificationOtp(String email) {
    String key = emailVerifyPrefix + email;
    cacheService.delete(key);
  }

  private void storePasswordResetOtp(String email, String otp) {
    String key = passwordResetPrefix + email;
    cacheService.set(key, otp, otpExpiryMinutes, TimeUnit.MINUTES);
  }

  private String getPasswordResetOtp(String email) {
    String key = passwordResetPrefix + email;
    return cacheService.get(key, String.class);
  }

  private boolean isPasswordResetOtpValid(String email, String inputOtp) {
    String key = passwordResetPrefix + email;
    String storedOtp = cacheService.get(key, String.class);
    return storedOtp != null && storedOtp.equals(inputOtp);
  }

  private void deletePasswordResetOtp(String email) {
    String key = passwordResetPrefix + email;
    cacheService.delete(key);
  }
}
