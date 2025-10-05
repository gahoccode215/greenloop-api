package com.greeloop.user.controller;

import com.greeloop.user.dto.request.*;
import com.greeloop.user.dto.response.ApiResponseDTO;
import com.greeloop.user.dto.response.AuthResponse;
import com.greeloop.user.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Authentication", description = "APIs for user authentication and authorization management")
public class AuthController {

    private final AuthService authService;
    private final RedisTemplate<String, Object> redisObjectTemplate;

    @PostMapping("/login")
    @Operation(
            summary = "User login",
            description = "Authenticate user with email and password, returns access token and refresh token"
    )

    public ResponseEntity<ApiResponseDTO<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Đăng nhập thành công", response, HttpStatus.OK)
        );
    }

    @Operation(
            summary = "Register new user",
            description = "Create new user account and send verification OTP to email"
    )
    @PostMapping("/register")
    public ResponseEntity<ApiResponseDTO<Void>> register(
            @Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(
                ApiResponseDTO.success("Đăng ký tài khoản thành công. Vui lòng kiểm tra email để kích hoạt", null, HttpStatus.CREATED)
        );
    }

    @Operation(
            summary = "Refresh access token",
            description = "Generate new access token using refresh token"
    )
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

    @Operation(
            summary = "User logout",
            description = "Invalidate current access token and refresh token"
    )
    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDTO<String>> logout(@RequestHeader("Authorization") String authHeader) {
        String accessToken = authHeader.substring(7);
        authService.logout(accessToken);
        return ResponseEntity.ok(ApiResponseDTO.success("Đăng xuất thành công", null, HttpStatus.OK));

    }

    @Operation(
            summary = "Change password",
            description = "Change user password with old password verification"
    )
    @PostMapping("/change-password")
    public ResponseEntity<ApiResponseDTO<String>> changePassword(@RequestHeader("Authorization") String authHeader, @Valid @RequestBody ChangePasswordRequest request) {
        String accessToken = authHeader.substring(7);
        authService.changePassword(accessToken, request);
        return ResponseEntity.ok(ApiResponseDTO.success("Đổi mật khẩu thành công", null, HttpStatus.OK));
    }

    @Operation(
            summary = "Verify email",
            description = "Verify user email with OTP code"
    )
    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponseDTO<String>> verifyEmail(@RequestBody VerifyEmailRequest request) {
        authService.verifyEmailOtp(request);
        return ResponseEntity.ok(ApiResponseDTO.success("Xác thực thành công", null, HttpStatus.OK));
    }

    @Operation(
            summary = "Resend verification OTP",
            description = "Resend email verification OTP to user email"
    )
    @PostMapping("/resend-verify-email-otp")
    public ResponseEntity<ApiResponseDTO<String>> resendOtp(@RequestBody ResendOtpRequest request) {
        authService.resendVerificationOtp(request.getEmail());
        return ResponseEntity.ok(ApiResponseDTO.success("Gửi lại mã OTP thành công. Vui lòng kiểm tra email", null, HttpStatus.OK));
    }

    @Operation(
            summary = "Forgot password",
            description = "Request password reset and send OTP to user email"
    )
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponseDTO<Void>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request);
        return ResponseEntity.ok(
                ApiResponseDTO.success("OTP đặt lại mật khẩu đã được gửi đến email của bạn", null, HttpStatus.OK)
        );
    }

    @Operation(
            summary = "Reset password",
            description = "Reset user password with OTP verification"
    )
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponseDTO<Void>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Mật khẩu đã được đặt lại thành công", null, HttpStatus.OK)
        );
    }

    @Operation(
            summary = "Resend password reset OTP",
            description = "Resend password reset OTP to user email"
    )
    @PostMapping("/resend-reset-password-otp")
    public ResponseEntity<ApiResponseDTO<Void>> resendPasswordResetOtp(@RequestBody ResendOtpRequest request) {
        authService.resendPasswordResetOtp(request.getEmail());
        return ResponseEntity.ok(
                ApiResponseDTO.success("Gửi lại OTP đặt lại mật khẩu thành công. Vui lòng kiểm tra email", null, HttpStatus.OK)
        );
    }

    @Operation(
            summary = "Exchange OAuth2 temporary key",
            description = "Exchange temporary key from OAuth2 login for access token and refresh token"
    )
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
