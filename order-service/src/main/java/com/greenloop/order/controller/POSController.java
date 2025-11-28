package com.greenloop.order.controller;

import com.greenloop.order.dto.request.order.offline.CreatePOSOrderRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.order.offline.POSOrderResponse;
import com.greenloop.order.service.POSService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
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
@RequestMapping("/api/v1/pos")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "POS", description = "Point of Sale - Bán hàng offline tại sự kiện")
@SecurityRequirement(name = "bearer-jwt")
public class POSController {

    private final POSService posService;

    @PostMapping("/orders")
    @Operation(
            summary = "Tạo đơn hàng offline",
            description = "Nhân viên tạo đơn tại sự kiện. Hỗ trợ: CASH, ECO_POINT, MIXED"
    )
    @PreAuthorize("hasAnyRole('ROLE_STAFF', 'ROLE_MANAGER' ,'ROLE_ADMIN')")
    public ResponseEntity<ApiResponseDTO<POSOrderResponse>> createPOSOrder(
            @Valid @RequestBody CreatePOSOrderRequest request) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long staffId = Long.valueOf(auth.getName());
        request.setStaffId(staffId);

        log.info("Staff {} creating POS order at event {}", staffId, request.getEventLocationId());

        POSOrderResponse response = posService.createPOSOrder(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Tạo đơn hàng thành công",
                        response,
                        HttpStatus.CREATED
                )
        );
    }

    @GetMapping("/orders/{orderId}")
    @Operation(
            summary = "Lấy chi tiết đơn hàng POS",
            description = "Xem thông tin đơn hàng offline theo orderId"
    )
    @PreAuthorize("hasAnyRole('ROLE_STAFF', 'ROLE_ADMIN', 'ROLE_CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<POSOrderResponse>> getPOSOrder(
            @PathVariable String orderId) {

        log.info("Fetching POS order: {}", orderId);

        POSOrderResponse response = posService.getPOSOrderById(orderId);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy đơn hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }
}
