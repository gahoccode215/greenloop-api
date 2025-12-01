package com.greenloop.reward.controller;

import com.greenloop.reward.dto.response.ApiResponseDTO;
import com.greenloop.reward.dto.response.EcoPointStatisticsResponse;
import com.greenloop.reward.dto.response.VoucherStatisticsResponse;
import com.greenloop.reward.service.DashboardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/rewards/dashboard")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Reward Dashboard Controller", description = "APIs for reward dashboard statistics")
public class DashboardController {

  private final DashboardService dashboardService;

  @GetMapping("/eco-points")
  @Operation(
      summary = "Get eco point statistics",
      description = "Retrieves statistics related to eco points.")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<EcoPointStatisticsResponse>> getEcoPointStatistics() {
    log.info("Received request to get eco point statistics");
    return ResponseEntity.ok(
        ApiResponseDTO.<EcoPointStatisticsResponse>builder()
            .data(dashboardService.getEcoPointStatistics())
            .message("EcoPoint statistics fetched successfully")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }

  @GetMapping("/vouchers")
  @Operation(
      summary = "Get voucher statistics",
      description = "Retrieves statistics related to vouchers.")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<VoucherStatisticsResponse>> getVoucherStatistics() {
    log.info("Received request to get voucher statistics");
    return ResponseEntity.ok(
        ApiResponseDTO.<VoucherStatisticsResponse>builder()
            .data(dashboardService.getVoucherStatistics())
            .message("Voucher statistics fetched successfully")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }
}
