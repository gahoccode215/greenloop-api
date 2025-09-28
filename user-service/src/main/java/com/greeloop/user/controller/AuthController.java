package com.greeloop.user.controller;

import com.greeloop.user.dto.request.*;
import com.greeloop.user.dto.response.ApiResponseDTO;
import com.greeloop.user.dto.response.AuthResponse;
import com.greeloop.user.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

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

}
