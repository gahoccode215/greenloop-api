package com.greenloop.user.controller;

import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.response.UserProfileResponse;
import com.greenloop.user.entity.User;
import com.greenloop.user.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Controller", description = "User API")
public class UserController {

  private final UserService userService;

  @GetMapping("/users/profile")
  public ResponseEntity<ApiResponseDTO<UserProfileResponse>> getMyProfile() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());

    UserProfileResponse response = userService.getMyProfile(userId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy thông tin cá nhân thành công", response, HttpStatus.OK));
  }

}
