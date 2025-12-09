package com.greenloop.user.controller;

import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.UserProfileResponse;
import com.greenloop.user.service.UserService;
import io.swagger.v3.oas.annotations.Hidden;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/internal/users")
@RequiredArgsConstructor
@Slf4j
public class UserInternalController {

    private final UserService userService;

    @GetMapping("/detail/{id}")
    public ResponseEntity<ApiResponseDTO<UserProfileResponse>> getUserDetailById(
            @PathVariable("id") Long id) {

        log.info("Internal API: Getting user detail for id: {}", id);

        UserProfileResponse user = userService.getMyProfile(id);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy thông tin khách hàng thành công",
                        user,
                        HttpStatus.OK
                )
        );
    }

    @Hidden
    @GetMapping("/all-ids")
    public ResponseEntity<List<Long>> getAllUserIds(
            @RequestHeader(value = "API_SECRET_HEADER", required = false) String apiSecret) {

        if (!"greenloopsecret".equals(apiSecret)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        List<Long> userIds = userService.getAllUserIds();
        return ResponseEntity.ok(userIds);
    }
}
