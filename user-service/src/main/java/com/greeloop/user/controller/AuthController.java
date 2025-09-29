package com.greeloop.user.controller;

import com.greeloop.user.dto.request.*;
import com.greeloop.user.dto.response.ApiResponseDTO;
import com.greeloop.user.dto.response.AuthResponse;
import com.greeloop.user.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final RedisTemplate<String, Object> redisObjectTemplate;

    @PostMapping("/login")
    public ResponseEntity<ApiResponseDTO<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Đăng nhập thành công", response, HttpStatus.OK)
        );
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponseDTO<Void>> register(
            @Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(
                ApiResponseDTO.success("Đăng ký tài khoản thành công. Vui lòng kiểm tra email để kích hoạt", null, HttpStatus.CREATED)
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponseDTO<AuthResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request, @RequestHeader(value = "Authorization") String authHeader) {

        log.info("Refresh request - Auth header: {}", authHeader);
        String oldAccessToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            oldAccessToken = authHeader.substring(7);
        }
        AuthResponse response = authService.refreshToken(request, oldAccessToken);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Làm mới token thành công", response, HttpStatus.OK)
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDTO<String>> logout(@RequestHeader("Authorization") String authHeader) {
        String accessToken = authHeader.substring(7);
        authService.logout(accessToken);
        return ResponseEntity.ok(ApiResponseDTO.success("Đăng xuất thành công", null, HttpStatus.OK));

    }

    @PostMapping("/change-password")
    public ResponseEntity<ApiResponseDTO<String>> changePassword(@RequestHeader("Authorization") String authHeader, @Valid @RequestBody ChangePasswordRequest request) {
        String accessToken = authHeader.substring(7);
        authService.changePassword(accessToken, request);
        return ResponseEntity.ok(ApiResponseDTO.success("Đổi mật khẩu thành công", null, HttpStatus.OK));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponseDTO<String>> verifyEmail(@RequestBody VerifyEmailRequest request) {
        authService.verifyEmailOtp(request.getEmail(), request.getOtp());
        return ResponseEntity.ok(ApiResponseDTO.success("Xác thực thành công", null, HttpStatus.OK));
    }

    @PostMapping("/resend-verify-email-otp")
    public ResponseEntity<ApiResponseDTO<String>> resendOtp(@RequestBody ResendOtpRequest request) {
        authService.resendVerificationOtp(request.getEmail());
        return ResponseEntity.ok(ApiResponseDTO.success("Gửi lại mã OTP thành công. Vui lòng kiểm tra email", null, HttpStatus.OK));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponseDTO<Void>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request);
        return ResponseEntity.ok(
                ApiResponseDTO.success("OTP đặt lại mật khẩu đã được gửi đến email của bạn", null, HttpStatus.OK)
        );
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponseDTO<Void>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Mật khẩu đã được đặt lại thành công", null, HttpStatus.OK)
        );
    }
    @PostMapping("/resend-reset-password-otp")
    public ResponseEntity<ApiResponseDTO<Void>> resendPasswordResetOtp(@RequestBody ResendOtpRequest request) {
        authService.resendPasswordResetOtp(request.getEmail());
        return ResponseEntity.ok(
                ApiResponseDTO.success("Gửi lại OTP đặt lại mật khẩu thành công. Vui lòng kiểm tra email", null, HttpStatus.OK)
        );
    }


    @PostMapping("/oauth2/exchange")
    public ResponseEntity<ApiResponseDTO<AuthResponse>> exchangeTempKey(@RequestParam String key, HttpServletRequest request) {
        try {
            String redisKey = "oauth2_success:" + key;
            Map<String, Object> tokenData = (Map<String, Object>) redisObjectTemplate.opsForValue().getAndDelete(redisKey);

            if (tokenData == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseDTO.error("Invalid or expired authentication key", HttpStatus.UNAUTHORIZED, request.getRequestURI() ));
            }

            AuthResponse response = AuthResponse.builder()
                    .accessToken((String) tokenData.get("accessToken"))
                    .refreshToken((String) tokenData.get("refreshToken"))
                    .type((String) tokenData.get("type"))
                    .userId((Long) tokenData.get("userId"))
                    .email((String) tokenData.get("email"))
                    .role((String) tokenData.get("role"))
                    .expiresIn((Long) tokenData.get("expiresIn"))
                    .refreshExpiresIn((Long) tokenData.get("refreshExpiresIn"))
                    .build();

            log.info("Successfully exchanged temp key for user: {}", tokenData.get("email"));
            return ResponseEntity.ok(
                    ApiResponseDTO.success("Successfully exchanged temp key", response, HttpStatus.OK)
            );

        } catch (Exception e) {
            log.error("Error exchanging temp key", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("Internal server error", HttpStatus.INTERNAL_SERVER_ERROR, request.getRequestURI()));
        }
    }

}
