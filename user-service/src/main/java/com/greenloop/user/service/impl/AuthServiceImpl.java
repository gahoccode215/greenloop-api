package com.greenloop.user.service.impl;

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
import com.greenloop.user.util.JwtUtil;
import com.greenloop.user.util.OtpUtil;

import java.util.List;
import java.util.concurrent.TimeUnit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.data.redis.core.RedisTemplate;
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
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${app.otp.expiry-in-minutes}")
    private long otpExpiryMinutes;

    @Value("${app.otp.redis.email-verification-prefix}")
    private String emailVerificationPrefix;

    @Value("${app.otp.redis.password-reset-prefix}")
    private String passwordResetPrefix;

    @Override
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(LoginException::new);

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new LoginException();
        }
        if (!user.getIsEmailVerified()) {
            throw new EmailNotVerifiedException();
        }

        if (!user.isActive()) {
            throw new AccountDisabledException();
        }
        if (user.getIsFirstLogin() != null && user.getIsFirstLogin()) {
            log.info("First login required for: {}", request.getEmail());
            throw new FirstLoginException("Tài khoản mới tạo yêu cầu đổi mật khẩu");
        }

        String accessToken = jwtUtil.generateToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        List<String> roleNames = user.getRoles().stream().map(Role::getName).toList();

        log.info("User logged in: {}", user.getEmail());

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
            throw new PasswordChangeException("Mật khẩu xác nhận không khớp");
        }
        if (userRepository.existsByPhone(request.getPhoneNumber())) {
            throw new PhoneNumberAlreadyExistsException(request.getPhoneNumber());
        }
        User user = userRepository.findByEmail(request.getEmail()).orElse(null);
        String emailVerificationOtp = otpUtil.generateOtp();
        if (user != null) {
            if (user.getIsEmailVerified()) {
                throw new EmailAlreadyExistsException();
            } else {
                // Email chưa xác thực, cập nhật OTP mới và gửi lại OTP
                user.setPassword(passwordEncoder.encode(request.getPassword()));
                userRepository.save(user);
                storeEmailVerificationOtp(user.getEmail(), emailVerificationOtp);
                log.info("Resend OTP for unverified email: {}", user.getEmail());
                UserRegistrationEvent event =
                        UserRegistrationEvent.builder()
                                .email(user.getEmail())
                                .otpCode(emailVerificationOtp)
                                .otpExpiryTime(otpUtil.getOtpExpiryTime())
                                .build();
                streamBridge.send("userRegistration-out-0", event);
                return;
            }
        }
        // Email chưa tồn tại, tạo user mới
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
                        .provider("LOCAL")
                        .build();
        userRepository.save(newUser);

        storeEmailVerificationOtp(newUser.getEmail(), emailVerificationOtp);
        log.info("New user registered: {}", newUser.getEmail());
        UserRegistrationEvent event =
                UserRegistrationEvent.builder()
                        .email(newUser.getEmail())
                        .otpCode(emailVerificationOtp)
                        .otpExpiryTime(otpUtil.getOtpExpiryTime())
                        .build();
        streamBridge.send("userRegistration-out-0", event);
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request, String oldAccessToken) {
        if (!jwtUtil.validateToken(request.getRefreshToken())
                || !jwtUtil.isRefreshToken(request.getRefreshToken())) {
            throw new InvalidCredentialsException();
        }

        if (oldAccessToken != null) {
            log.info("Attempting to blacklist old access token");
            jwtUtil.blacklistToken(oldAccessToken);
        }

        // Extract user từ token
        String email = jwtUtil.extractUsername(request.getRefreshToken());
        User user = userRepository.findByEmail(email).orElseThrow(InvalidCredentialsException::new);

        if (!user.isActive()) {
            throw new AccountDisabledException();
        }

        // Generate access token mới
        String newAccessToken = jwtUtil.generateToken(user);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .type("Bearer")
                .expiresIn(jwtUtil.getExpirationTime())
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
            throw new PasswordChangeException("Mật khẩu xác nhận không khớp");
        }
        User user =
                userRepository
                        .findByEmail(email)
                        .orElseThrow(() -> new UsernameNotFoundException("User không tồn tại " + email));
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new PasswordChangeException("Mật khẩu hiện tại không đúng");
        }
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new PasswordChangeException("Mật khẩu mới phải khác mật khẩu hiện tại");
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        if (user.getIsFirstLogin() != null && user.getIsFirstLogin()) {
            user.setIsFirstLogin(false);
        }
        userRepository.save(user);

        // Blacklist force logout
        //        jwtUtil.blacklistToken(accessToken);
        log.info("Password changed successfully for user: {}", email);
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
        log.info("Resend OTP for unverified email: {}", email);
        streamBridge.send("userRegistration-out-0", event);
    }

    @Override
    @Transactional
    public void resendPasswordResetOtp(String email) {
        User user =
                userRepository.findByEmail(email).orElseThrow(() -> new EmailNotFoundException(email));
        if (!user.isActive()) {
            throw new AccountDisabledException();
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

        log.info("Resent password reset OTP for: {}", email);
    }

    @Override
    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        User user =
                userRepository
                        .findByEmail(request.getEmail())
                        .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));
        if (!user.isActive()) {
            throw new AccountDisabledException();
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
        log.info("Verifying password reset OTP for: {}", request.getEmail());

        User user =
                userRepository
                        .findByEmail(request.getEmail())
                        .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));

        // Verify OTP
        if (!isPasswordResetOtpValid(request.getEmail(), request.getOtp())) {
            throw new PasswordResetException("Mã OTP không đúng hoặc đã hết hạn", "INVALID_OTP");
        }

        log.info("Password reset OTP verified for: {}", request.getEmail());
    }

    @Override
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        log.info("Resetting password for: {}", request.getEmail());

        // Validate confirm password
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new PasswordChangeException("Mật khẩu xác nhận không khớp");
        }

        // Find user
        User user =
                userRepository
                        .findByEmail(request.getEmail())
                        .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        deletePasswordResetOtp(request.getEmail());

        log.info("Password reset successful for: {}", request.getEmail());
    }

    @Override
    @Transactional
    public void changePasswordFirstTime(ChangePasswordFirstTimeRequest request) {
        log.info("First time password change for: {}", request.getEmail());

        // Validate password confirm
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new PasswordChangeException("Mật khẩu xác nhận không khớp");
        }

        // Tìm user
        User user =
                userRepository
                        .findByEmail(request.getEmail())
                        .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));
        if (user.getIsFirstLogin() == null || !user.getIsFirstLogin()) {
            throw new PasswordChangeException("Tài khoản này đã đổi mật khẩu rồi");
        }

        // Validate temporary password
        if (!passwordEncoder.matches(request.getTemporaryPassword(), user.getPassword())) {
            throw new PasswordChangeException("Mật khẩu tạm thời không đúng");
        }

        // Validate new password khác temporary password
        if (request.getNewPassword().equals(request.getTemporaryPassword())) {
            throw new PasswordChangeException("Mật khẩu mới phải khác mật khẩu tạm thời");
        }

        // Update password + set isFirstLogin = false
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setIsFirstLogin(false);
        userRepository.save(user);

        log.info("First time password change completed for user: {}", request.getEmail());
    }

    private void storeEmailVerificationOtp(String email, String otp) {
        String key = emailVerificationPrefix + email;
        redisTemplate.opsForValue().set(key, otp, otpExpiryMinutes, TimeUnit.MINUTES);
    }

    private boolean isEmailVerificationOtpValid(String email, String inputOtp) {
        String key = emailVerificationPrefix + email;
        String storedOtp = redisTemplate.opsForValue().get(key);
        return storedOtp != null && storedOtp.equals(inputOtp);
    }

    private void deleteEmailVerificationOtp(String email) {
        String key = emailVerificationPrefix + email;
        redisTemplate.delete(key);
    }

    private void storePasswordResetOtp(String email, String otp) {
        String key = passwordResetPrefix + email;
        redisTemplate.opsForValue().set(key, otp, otpExpiryMinutes, TimeUnit.MINUTES);
    }

    private String getPasswordResetOtp(String email) {
        String key = passwordResetPrefix + email;
        return redisTemplate.opsForValue().get(key);
    }

    private boolean isPasswordResetOtpValid(String email, String inputOtp) {
        String key = passwordResetPrefix + email;
        String storedOtp = redisTemplate.opsForValue().get(key);
        return storedOtp != null && storedOtp.equals(inputOtp);
    }

    private void deletePasswordResetOtp(String email) {
        String key = passwordResetPrefix + email;
        redisTemplate.delete(key);
    }
}
