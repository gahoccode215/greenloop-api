package com.greenloop.user.controller;

import com.greenloop.user.dto.request.UpdateProfileRequest;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.UserProfileResponse;
import com.greenloop.user.service.UserService;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Controller", description = "User API")
public class UserController {

  private final UserService userService;

  @GetMapping("/profile")
  @PreAuthorize("isAuthenticated()")
  @Operation(summary = "Get current user profile")
  public ResponseEntity<ApiResponseDTO<UserProfileResponse>> getMyProfile() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());

    log.info("Getting profile for user: {}", userId);

    UserProfileResponse response = userService.getMyProfile(userId);

    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy thông tin cá nhân thành công", response, HttpStatus.OK));
  }

  @PutMapping("/profile")
  @PreAuthorize("isAuthenticated()")
  @Operation(summary = "Update current user profile")
  public ResponseEntity<ApiResponseDTO<UserProfileResponse>> updateProfile(
      @Valid @RequestBody UpdateProfileRequest request) {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());

    log.info("Updating profile for user: {}", userId);

    UserProfileResponse response = userService.updateProfile(userId, request);

    return ResponseEntity.ok(
        ApiResponseDTO.success("Cập nhật thông tin cá nhân thành công", response, HttpStatus.OK));
  }

  @Hidden
  @GetMapping("/users/{id}/info")
  public ResponseEntity<UserProfileResponse> getUserInfoById(
      @PathVariable("id") Long id,
      @RequestHeader(value = "API_SECRET_HEADER", required = false) String apiSecret) {

    if (!"greenloopsecret".equals(apiSecret)) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    UserProfileResponse response = userService.getMyProfile(id);
    return ResponseEntity.ok(response);
  }
}
