package com.greeloop.user.controller;

import com.greeloop.user.dto.request.UpdateUserRequest;
import com.greeloop.user.dto.response.ApiResponseDTO;
import com.greeloop.user.dto.response.UserProfileResponse;
import com.greeloop.user.dto.response.UserResponse;
import com.greeloop.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
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

    @Operation(
            summary = "Get user by ID",
            description = "Get detailed information of a specific user. Access control: ADMIN can view all, MANAGER can view STAFF and CUSTOMER, STAFF can view CUSTOMER only"
    )
    @GetMapping("/{userId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
    public ResponseEntity<ApiResponseDTO<UserResponse>> getUserById(
            @PathVariable Long userId,
            Authentication authentication) {

        String currentUserRole = getCurrentRole(authentication);


        log.info("User {} (role: {}) requesting user details for userId: {}",
                authentication.getName(), currentUserRole, userId);

        UserResponse user = userService.getUserById(userId, currentUserRole);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy thông tin người dùng thành công", user, HttpStatus.OK)
        );
    }

    @Operation(
            summary = "Update user",
            description = "Update user info. Only ADMIN, MANAGER (with permission) can update"
    )
    @PutMapping("/{userId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<UserResponse>> updateUser(
            @PathVariable Long userId,
            @RequestBody UpdateUserRequest request,
            Authentication authentication) {

        String currentUserRole = getCurrentRole(authentication);


        UserResponse user = userService.updateUser(userId, request, currentUserRole);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Cập nhật thông tin người dùng thành công", user, HttpStatus.OK)
        );
    }

    @Operation(
            summary = "Update user status",
            description = "Activate or deactivate a user account. Only ADMIN, MANAGER (with permission) can update"
    )
    @PatchMapping("/{userId}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> updateUserStatus(
            @PathVariable Long userId,
            @RequestParam("status") Boolean status,
            Authentication authentication) {

        String currentUserRole = getCurrentRole(authentication);

        userService.updateUserStatus(userId, currentUserRole, status);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Cập nhật trạng thái tài khoản thành công", null, HttpStatus.OK)
        );
    }



    @Operation(
            summary = "Get all users",
            description = "Get paginated list of users. Access filtered by role: ADMIN sees all, MANAGER sees STAFF and CUSTOMER, STAFF sees CUSTOMER only"
    )
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
    public ResponseEntity<ApiResponseDTO<Page<UserResponse>>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "userId") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDir,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String role,
            Authentication authentication) {

        String currentUserRole = getCurrentRole(authentication);


        log.info("User {} (role: {}) requesting users list with role filter: {}",
                authentication.getName(), currentUserRole, role);

        Page<UserResponse> users = userService.getAllUsers(
                page, size, sortBy, sortDir, email, role, currentUserRole
        );

        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy danh sách tài khoản thành công", users, HttpStatus.OK)
        );
    }

    private String getCurrentRole(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .findFirst()
                .map(auth -> auth.getAuthority().replace("ROLE_", ""))
                .orElse("");
    }


}
