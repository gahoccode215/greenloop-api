package com.greenloop.notification.controller;

import com.greenloop.notification.dto.request.TokenRequest;
import com.greenloop.notification.dto.response.ApiResponseDTO;
import com.greenloop.notification.dto.response.NotificationResponse;
import com.greenloop.notification.service.NotificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/api/v1/notifications")
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Notification Controller", description = "APIs for managing notifications")
public class NotificationController {
    private final NotificationService notificationService;

    @PostMapping("/register-token")
    @Operation(
            summary = "Register FCM Token",
            description = "Save FCM token for a user",
            tags = {"Notification"})
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponseDTO<String>> registerToken(@RequestBody @Valid TokenRequest request) {
        notificationService.registerToken(request);
        return ResponseEntity.ok(ApiResponseDTO.<String>builder()
                .data("Token đã được đăng ký thành công")
                        .success(true)
                        .statusCode(HttpStatus.OK.value())
                .build());
    }

    @GetMapping
    @Operation(
            summary = "Get Notifications by User",
            description = "Retrieve notifications for a user with pagination",
            tags = {"Notification"})
    public ResponseEntity<ApiResponseDTO<Page<NotificationResponse>>> getNotifications(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDir) {

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
        Page<NotificationResponse> notifications = notificationService.getNotifications(pageable);
        return ResponseEntity.ok(ApiResponseDTO.<Page<NotificationResponse>>builder()
                .data(notifications)
                .success(true)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @PutMapping("/{id}/read")
    @Operation(
            summary = "Mark Notification as Read",
            description = "Update notification status to read",
            tags = {"Notification"})
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponseDTO<Void>> markAsRead(@PathVariable Long id) {
        notificationService.markAsRead(id);
        return ResponseEntity.ok()
                .body(ApiResponseDTO.<Void>builder()
                        .data(null)
                        .success(true)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @PutMapping
    @Operation(
            summary = "Mark All Notifications as Read",
            description = "Update all notifications status to read for the user",
            tags = {"Notification"})
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponseDTO<Void>> markAllAsRead() {
        notificationService.markAllAsRead();
        return ResponseEntity.ok()
                .body(ApiResponseDTO.<Void>builder()
                        .data(null)
                        .success(true)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }


    @DeleteMapping("/remove-token")
    @Operation(
            summary = "Remove FCM Token",
            description = "Delete a token when user logs out",
            tags = {"Notification"})
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponseDTO<String>> removeToken(@RequestParam String token) {
        notificationService.unregisterToken(token);
        return ResponseEntity.ok(ApiResponseDTO.<String>builder()
                .data("Token đã được xóa thành công")
                .success(true)
                .statusCode(HttpStatus.OK.value())
                .build());
    }


}
