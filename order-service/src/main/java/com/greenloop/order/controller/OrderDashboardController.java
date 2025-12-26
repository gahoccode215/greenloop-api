package com.greenloop.order.controller;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.dashboard.OrderDashboardOverviewResponse;
import com.greenloop.order.service.OrderDashboardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/orders/dashboard")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Order Dashboard", description = "Dashboard quản lý thống kê đơn hàng")
public class OrderDashboardController {

    private final OrderDashboardService dashboardService;

    @GetMapping("/overview")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(summary = "Lấy thống kê tổng quan đơn hàng")
    public ResponseEntity<ApiResponseDTO<OrderDashboardOverviewResponse>> getDashboardOverview() {
        OrderDashboardOverviewResponse response = dashboardService.getDashboardOverview();
        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy thống kê đơn hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }
}
