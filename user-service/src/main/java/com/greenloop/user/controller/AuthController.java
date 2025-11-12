package com.greenloop.user.controller;

import com.greenloop.user.dto.request.*;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.AuthResponse;
import com.greenloop.user.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(
    name = "Authentication",
    description = "APIs for user authentication and authorization management")
public class AuthController {

  private final AuthService authService;
  private final RedisTemplate<String, Object> redisObjectTemplate;

  @PostMapping("/login")
  @Operation(
      summary = "User login",
      description =
          "Authenticate user with email and password, returns access token and refresh token")
  public ResponseEntity<ApiResponseDTO<AuthResponse>> login(
      @Valid @RequestBody LoginRequest request) {
    AuthResponse response = authService.login(request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Đăng nhập thành công", response, HttpStatus.OK));
  }

  @Operation(
      summary = "Register new user",
      description = "Create new user account and send verification OTP to email")
  @PostMapping("/register")
  public ResponseEntity<ApiResponseDTO<Void>> register(
      @Valid @RequestBody RegisterRequest request) {
    authService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(
            ApiResponseDTO.success(
                "Đăng ký tài khoản thành công. Vui lòng kiểm tra email để kích hoạt",
                null,
                HttpStatus.CREATED));
  }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponseDTO<AuthResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Làm mới token thành công", response, HttpStatus.OK));
    }


    @Operation(
      summary = "User logout",
      description = "Invalidate current access token and refresh token")
  @PostMapping("/logout")
  public ResponseEntity<ApiResponseDTO<String>> logout(HttpServletRequest httpRequest) {
    String accessToken = extractToken(httpRequest);
    authService.logout(accessToken);
    return ResponseEntity.ok(ApiResponseDTO.success("Đăng xuất thành công", null, HttpStatus.OK));
  }

  @Operation(
      summary = "Change password",
      description = "Change user password with old password verification")
  @PostMapping("/change-password")
  public ResponseEntity<ApiResponseDTO<String>> changePassword(
      HttpServletRequest httpRequest, @Valid @RequestBody ChangePasswordRequest request) {
    String accessToken = extractToken(httpRequest);
    authService.changePassword(accessToken, request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Đổi mật khẩu thành công", null, HttpStatus.OK));
  }

  @Operation(summary = "Verify email", description = "Verify user email with OTP code")
  @PostMapping("/verify-email")
  public ResponseEntity<ApiResponseDTO<String>> verifyEmail(
      @RequestBody VerifyEmailRequest request) {
    authService.verifyEmailOtp(request);
    return ResponseEntity.ok(ApiResponseDTO.success("Xác thực thành công", null, HttpStatus.OK));
  }

  @Operation(
      summary = "Resend verification OTP",
      description = "Resend email verification OTP to user email")
  @PostMapping("/resend-verify-email-otp")
  public ResponseEntity<ApiResponseDTO<String>> resendOtp(@RequestBody ResendOtpRequest request) {
    authService.resendVerificationOtp(request.getEmail());
    return ResponseEntity.ok(
        ApiResponseDTO.success(
            "Gửi lại mã OTP thành công. Vui lòng kiểm tra email", null, HttpStatus.OK));
  }

  @Operation(
      summary = "Forgot password",
      description = "Request password reset and send OTP to user email")
  @PostMapping("/forgot-password")
  public ResponseEntity<ApiResponseDTO<Void>> forgotPassword(
      @Valid @RequestBody ForgotPasswordRequest request) {
    authService.forgotPassword(request);
    return ResponseEntity.ok(
        ApiResponseDTO.success(
            "OTP đặt lại mật khẩu đã được gửi đến email của bạn", null, HttpStatus.OK));
  }

  @PostMapping("/verify-reset-otp")
  @Operation(summary = "Verify password reset OTP (optional)")
  public ResponseEntity<ApiResponseDTO<Void>> verifyPasswordResetOtp(
      @Valid @RequestBody VerifyPasswordResetOtpRequest request) {
    authService.verifyPasswordResetOtp(request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Xác thực OTP thành công", null, HttpStatus.OK));
  }

  @Operation(summary = "Reset password", description = "Reset user password with OTP verification")
  @PostMapping("/reset-password")
  public ResponseEntity<ApiResponseDTO<Void>> resetPassword(
      @Valid @RequestBody ResetPasswordRequest request) {
    authService.resetPassword(request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Mật khẩu đã được đặt lại thành công", null, HttpStatus.OK));
  }

  @Operation(
      summary = "Resend password reset OTP",
      description = "Resend password reset OTP to user email")
  @PostMapping("/resend-reset-password-otp")
  public ResponseEntity<ApiResponseDTO<Void>> resendPasswordResetOtp(
      @RequestBody ResendOtpRequest request) {
    authService.resendPasswordResetOtp(request.getEmail());
    return ResponseEntity.ok(
        ApiResponseDTO.success(
            "Gửi lại OTP đặt lại mật khẩu thành công. Vui lòng kiểm tra email",
            null,
            HttpStatus.OK));
  }

  @PostMapping("/change-password-first-time")
  @Operation(summary = "Change password  (for new employees)")
  public ResponseEntity<ApiResponseDTO<Void>> changePasswordFirstTime(
      @Valid @RequestBody ChangePasswordFirstTimeRequest request) {
    log.info("Changing first time password for: {}", request.getEmail());
    authService.changePasswordFirstTime(request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Đổi mật khẩu thành công", null, HttpStatus.OK));
  }

  @Operation(
      summary = "Exchange OAuth2 temporary key",
      description = "Exchange temporary key from OAuth2 login for access token and refresh token")
  @PostMapping("/oauth2/exchange")
  public ResponseEntity<ApiResponseDTO<AuthResponse>> exchangeTempKey(
      @RequestParam String key, HttpServletRequest request) {
    try {
      // Validate key format
      if (key == null || key.isBlank()) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(
                ApiResponseDTO.error(
                    "Missing or invalid key parameter",
                    HttpStatus.BAD_REQUEST,
                    request.getRequestURI()));
      }

      String redisKey = "oauth2_success:" + key;
      Map<String, Object> tokenData =
          (Map<String, Object>) redisObjectTemplate.opsForValue().getAndDelete(redisKey);

      if (tokenData == null) {
        log.warn("Invalid or expired OAuth2 key: {}", key);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(
                ApiResponseDTO.error(
                    "Invalid or expired authentication key",
                    HttpStatus.UNAUTHORIZED,
                    request.getRequestURI()));
      }

      AuthResponse response =
          AuthResponse.builder()
              .accessToken((String) tokenData.get("accessToken"))
              .refreshToken((String) tokenData.get("refreshToken"))
              .type((String) tokenData.get("type"))
              .userId(((Number) tokenData.get("userId")).longValue())
              .email((String) tokenData.get("email"))
              .roles(castRoles(tokenData.get("roles")))
              .expiresIn(((Number) tokenData.get("expiresIn")).longValue())
              .refreshExpiresIn(((Number) tokenData.get("refreshExpiresIn")).longValue())
              .build();

      log.info("Successfully exchanged temp key for user: {}", tokenData.get("email"));
      return ResponseEntity.ok(
          ApiResponseDTO.success("Trao đổi key thành công", response, HttpStatus.OK));

    } catch (ClassCastException e) {
      log.error("Type casting error in token data: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(
              ApiResponseDTO.error(
                  "Token data format error",
                  HttpStatus.INTERNAL_SERVER_ERROR,
                  request.getRequestURI()));
    } catch (Exception e) {
      log.error("Error exchanging temp key", e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(
              ApiResponseDTO.error(
                  "Internal server error",
                  HttpStatus.INTERNAL_SERVER_ERROR,
                  request.getRequestURI()));
    }
  }

  private String extractToken(HttpServletRequest request) {
    String authHeader = request.getHeader("Authorization");
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
      return authHeader.substring(7);
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private List<String> castRoles(Object rolesObj) {
    if (rolesObj instanceof List<?>) {
      return ((List<?>) rolesObj).stream().map(Object::toString).toList();
    }
    if (rolesObj instanceof String str) {
      return List.of(str.split(","));
    }
    return List.of();
  }
}
