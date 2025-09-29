package com.greeloop.user.service.impl;


import com.greeloop.user.constant.RoleConstants;
import com.greeloop.user.dto.event.PasswordResetEvent;
import com.greeloop.user.dto.event.UserRegistrationEvent;
import com.greeloop.user.dto.request.*;
import com.greeloop.user.dto.response.AuthResponse;
import com.greeloop.user.entity.Role;
import com.greeloop.user.entity.User;
import com.greeloop.user.exception.*;
import com.greeloop.user.repository.RoleRepository;
import com.greeloop.user.repository.UserRepository;
import com.greeloop.user.service.AuthService;
import com.greeloop.user.util.JwtUtil;
import com.greeloop.user.util.OtpUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

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


    @Override
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new LoginException();
        }
        if(!user.getIsEmailVerified()){
            throw new EmailNotVerifiedException();
        }

        if (!user.getIsActive()) {
            throw new AccountDisabledException();
        }

        // Generate JWT token
        String accessToken = jwtUtil.generateToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        log.info("User logged in: {}", user.getEmail());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .type("Bearer")
                .userId(user.getId())
                .email(user.getEmail())
                .role(user.getRole().getName())
                .expiresIn(jwtUtil.getExpirationTime())
                .refreshExpiresIn(jwtUtil.getRefreshExpirationTime())
                .build();
    }

    @Transactional
    @Override
    public void register(RegisterRequest request) {
        User user = userRepository.findByEmail(request.getEmail()).orElse(null);
        if (user != null) {
            if (user.getIsEmailVerified()) {
                throw new EmailAlreadyExistsException();
            } else {
                // Email chưa xác thực, cập nhật OTP mới và gửi lại OTP
                String emailVerificationOtp = otpUtil.generateOtp();
                LocalDateTime emailVerificationOtpExpiresAt = otpUtil.getOtpExpiryTime();
                user.setPassword(passwordEncoder.encode(request.getPassword()));
                user.setEmailVerificationToken(emailVerificationOtp);
                user.setEmailVerificationTokenExpiresAt(emailVerificationOtpExpiresAt);
                userRepository.save(user);
                log.info("Resend OTP for unverified email: {}", user.getEmail());
                UserRegistrationEvent event = UserRegistrationEvent.builder()
                        .email(user.getEmail())
                        .otpCode(emailVerificationOtp)
                        .otpExpiryTime(emailVerificationOtpExpiresAt)
                        .build();
                streamBridge.send("userRegistration-out-0", event);
                return;
            }
        }
        // Email chưa tồn tại, tạo user mới
        Role userRole = roleRepository.findByName(RoleConstants.USER)
                .orElseThrow(() -> new RoleNotFoundException(RoleConstants.USER));
        String emailVerificationOtp = otpUtil.generateOtp();
        LocalDateTime emailVerificationOtpExpiresAt = otpUtil.getOtpExpiryTime();
        User newUser = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(userRole)
                .isActive(false)
                .isEmailVerified(false)
                .emailVerificationToken(emailVerificationOtp)
                .emailVerificationTokenExpiresAt(emailVerificationOtpExpiresAt)
                .provider("LOCAL")
                .build();
        userRepository.save(newUser);
        log.info("New user registered: {}", newUser.getEmail());
        UserRegistrationEvent event = UserRegistrationEvent.builder()
                .email(newUser.getEmail())
                .otpCode(emailVerificationOtp)
                .otpExpiryTime(emailVerificationOtpExpiresAt)
                .build();
        streamBridge.send("userRegistration-out-0", event);

    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request, String oldAccessToken) {
        if (!jwtUtil.validateToken(request.getRefreshToken()) ||
                !jwtUtil.isRefreshToken(request.getRefreshToken())) {
            throw new InvalidCredentialsException();
        }

        if (oldAccessToken != null) {
            log.info("Attempting to blacklist old access token");
            jwtUtil.blacklistToken(oldAccessToken);
        }

        // Extract user từ token
        String email = jwtUtil.extractUsername(request.getRefreshToken());
        User user = userRepository.findByEmail(email)
                .orElseThrow(InvalidCredentialsException::new);

        if (!user.getIsActive()) {
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
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User không tồn tại " + email));
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new PasswordChangeException("Mật khẩu hiện tại không đúng");
        }
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new PasswordChangeException("Mật khẩu mới phải khác mật khẩu hiện tại");
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Blacklist force logout
//        jwtUtil.blacklistToken(accessToken);
        log.info("Password changed successfully for user: {}", email);
    }

    @Override
    @Transactional
    public void verifyEmailOtp(String email, String otp) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EmailNotFoundException(email));
        if (user.getIsEmailVerified()) {
            throw new VerifyEmailException("Email đã được xác thực", "EMAIL_ALREADY_VERIFIED");
        }
        if (!user.getEmailVerificationToken().equals(otp)) {
            throw new VerifyEmailException("Mã OTP không đúng", "INVALID_OTP");
        }
        if (user.getEmailVerificationTokenExpiresAt().isBefore(LocalDateTime.now())) {
            throw new VerifyEmailException("Mã OTP đã hết hạn", "OTP_EXPIRED");
        }
        user.setIsEmailVerified(true);
        user.setIsActive(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationTokenExpiresAt(null);
        userRepository.save(user);
    }

    @Override
    @Transactional
    public void resendVerificationOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EmailNotFoundException(email));
        if (user.getIsEmailVerified()) {
            throw new VerifyEmailException("Email đã được xác thực", "EMAIL_ALREADY_VERIFIED");
        }
        String newOtp = otpUtil.generateOtp();
        LocalDateTime newExpiry = otpUtil.getOtpExpiryTime();
        user.setEmailVerificationToken(newOtp);
        user.setEmailVerificationTokenExpiresAt(newExpiry);
        userRepository.save(user);
        UserRegistrationEvent event = UserRegistrationEvent.builder()
                .email(user.getEmail())
                .otpCode(newOtp)
                .otpExpiryTime(newExpiry)
                .build();
        streamBridge.send("userRegistration-out-0", event);
    }

    @Override
    @Transactional
    public void resendPasswordResetOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EmailNotFoundException(email));
        if (!user.getIsActive()) {
            throw new AccountDisabledException();
        }
        if (user.getPasswordResetOtp() == null) {
            throw new PasswordResetException("Không có yêu cầu đặt lại mật khẩu trước đó", "NO_RESET_REQUEST");
        }
        String newPasswordResetOtp = otpUtil.generateOtp();
        LocalDateTime newPasswordResetExpiry = otpUtil.getOtpExpiryTime();

        user.setPasswordResetOtp(newPasswordResetOtp);
        user.setPasswordResetOtpExpiresAt(newPasswordResetExpiry);

        userRepository.save(user);

        PasswordResetEvent event = PasswordResetEvent.builder()
                .email(user.getEmail())
                .otpCode(newPasswordResetOtp)
                .otpExpiryTime(newPasswordResetExpiry)
                .build();

        streamBridge.send("passwordReset-out-0", event);

        log.info("Resent password reset OTP for: {}", email);
    }

    @Override
    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));
        if (!user.getIsActive()) {
            throw new AccountDisabledException();
        }
        String passwordResetOtp = otpUtil.generateOtp();
        LocalDateTime passwordResetOtpExpiresAt = otpUtil.getOtpExpiryTime();

        user.setPasswordResetOtp(passwordResetOtp);
        user.setPasswordResetOtpExpiresAt(passwordResetOtpExpiresAt);

        userRepository.save(user);

        PasswordResetEvent event = PasswordResetEvent.builder()
                .email(user.getEmail())
                .otpCode(passwordResetOtp)
                .otpExpiryTime(passwordResetOtpExpiresAt)
                .build();

        streamBridge.send("passwordReset-out-0", event);
    }

    @Override
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new EmailNotFoundException(request.getEmail()));
        if (user.getPasswordResetOtp() == null) {
            throw new PasswordResetException("Không có yêu cầu đặt lại mật khẩu", "NO_RESET_REQUEST");
        }
        if (!user.getPasswordResetOtp().equals(request.getOtp())) {
            throw new PasswordResetException("Mã OTP không đúng", "INVALID_OTP");
        }
        if (user.getPasswordResetOtpExpiresAt().isBefore(LocalDateTime.now())) {
            user.setPasswordResetOtp(null);
            user.setPasswordResetOtpExpiresAt(null);
            userRepository.save(user);
            throw new PasswordResetException("Mã OTP đã hết hạn", "OTP_EXPIRED");
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordResetOtp(null);
        user.setPasswordResetOtpExpiresAt(null);
        userRepository.save(user);
        log.info("Password reset successful for: {}", request.getEmail());
    }


}
