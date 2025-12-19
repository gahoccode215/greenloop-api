package com.greenloop.user.controller;

import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.dashboard.UserDashboardOverviewResponse;
import com.greenloop.user.service.UserDashboardService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users/dashboard")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Dashboard", description = "Dashboard quản lý thống kê người dùng")
public class UserDashboardController {

  private final UserDashboardService dashboardService;

  @GetMapping("/overview")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
  public ResponseEntity<ApiResponseDTO<UserDashboardOverviewResponse>> getDashboardOverview() {

    UserDashboardOverviewResponse response = dashboardService.getDashboardOverview();

    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy thống kê người dùng thành công", response, HttpStatus.OK));
  }
}
