package com.greenloop.user.controller;

import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.response.UserProfileResponse;
import com.greenloop.user.entity.User;
import com.greenloop.user.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

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
                ApiResponseDTO.success("Lấy thông tin cá nhân thành công", response, HttpStatus.OK)
        );
    }

    @PostMapping("/admin/users")
    public ResponseEntity<ApiResponseDTO<CreateEmployeeResponse>> createUser(@RequestBody CreateEmployeeRequest request) {
        CreateEmployeeResponse response = userService.createEmployee(request);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Tạo tài khoản nhân viên thành công", response, HttpStatus.OK)
        );
    }
    @GetMapping("/admin/users")
    public ResponseEntity<ApiResponseDTO<List<User>>> getAllUser() {
        List<User> response = userService.getAllUser();
        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy thông tin tất cả người dùng thành công", response, HttpStatus.OK)
        );
    }


}
