package com.greenloop.order.controller;

import com.greenloop.order.dto.request.CreateOrderOfflineRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.OrderOfflineResponse;
import com.greenloop.order.service.OrderOfflineService;
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
@RequestMapping("/api/v1/orders/offline")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Order Offline", description = "Offline Order APIs for Staff")
public class OrderOfflineController {

    private final OrderOfflineService orderOfflineService;

    @PostMapping
    @Operation(
            summary = "Create offline order",
            description = "Tạo đơn hàng offline tại sự kiện bởi Staff"
    )
//    @PreAuthorize("hasAnyRole('STAFF', 'MANAGER', 'ADMIN')")
    public ResponseEntity<ApiResponseDTO<OrderOfflineResponse>> createOrderOffline(
            @Valid @RequestBody CreateOrderOfflineRequest request) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Staff {} creating offline order for customer: {}, event: {}",
                auth.getName(), request.getCustomerId(), request.getEventId());

        OrderOfflineResponse response = orderOfflineService.createOrderOffline(request);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Tạo đơn hàng offline thành công",
                response,
                HttpStatus.CREATED
        ));
    }
}
