package com.greeloop.user.controller;

import com.greeloop.user.dto.response.ApiResponseDTO;
import com.greeloop.user.dto.response.UserProfileResponse;
import com.greeloop.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    @GetMapping("/profile")
    public ResponseEntity<ApiResponseDTO<UserProfileResponse>> getMyProfile() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());

        UserProfileResponse response = userService.getMyProfile(userId);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy thông tin cá nhân thành công", response, HttpStatus.OK)
        );
    }


}
