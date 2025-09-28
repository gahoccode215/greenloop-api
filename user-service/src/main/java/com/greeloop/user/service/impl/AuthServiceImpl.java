package com.greeloop.user.service.impl;


import com.greeloop.user.constant.RoleConstants;
import com.greeloop.user.dto.event.UserRegistrationEvent;
import com.greeloop.user.dto.request.ChangePasswordRequest;
import com.greeloop.user.dto.request.LoginRequest;
import com.greeloop.user.dto.request.RefreshTokenRequest;
import com.greeloop.user.dto.request.RegisterRequest;
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
import lombok.Value;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

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
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException();
        }

        Role userRole = roleRepository.findByName(RoleConstants.USER)
                .orElseThrow(() -> new RoleNotFoundException(RoleConstants.USER));
        // Generate OTP
        String emailVerificationOtp  = otpUtil.generateOtp();
        LocalDateTime emailVerificationOtpExpiresAt  = otpUtil.getOtpExpiryTime();

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(userRole)
                .isActive(false)
                .isEmailVerified(false)
                .emailVerificationToken(emailVerificationOtp)
                .emailVerificationTokenExpiresAt(emailVerificationOtpExpiresAt)
                .build();

        user = userRepository.save(user);

        log.info("New user registered: {}", user.getEmail());

        UserRegistrationEvent userRegistrationEvent = UserRegistrationEvent.builder()
                        .email(user.getEmail())
                        .otpCode(emailVerificationOtp)
                        .otpExpiryTime(emailVerificationOtpExpiresAt)
                        .build();


        streamBridge.send("userRegistration-out-0", userRegistrationEvent);

    }

    @Override
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
    public void verifyEmailOtp(String email, String otp) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EmailNotFoundException(email));
        if (user.getIsEmailVerified()) {
            throw new VerifyEmailException("Email đã được xác thực", "INVALID_OTP");
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


}
