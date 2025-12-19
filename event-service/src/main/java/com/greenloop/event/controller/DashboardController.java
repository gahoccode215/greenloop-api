package com.greenloop.event.controller;

import com.greenloop.event.dto.response.ApiResponseDTO;
import com.greenloop.event.dto.response.EventRegistrationStatisticsResponse;
import com.greenloop.event.dto.response.EventStaffStatisticsResponse;
import com.greenloop.event.dto.response.EventStatisticsResponse;
import com.greenloop.event.service.DashboardService;
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
@RequestMapping("/api/v1/events/dashboard")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Dashboard Controller", description = "APIs for event dashboard statistics")
public class DashboardController {
  private final DashboardService dashboardService;

  @GetMapping("/events")
  @Operation(
      summary = "Get event statistics",
      description = "Retrieves various statistics related to events.")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<EventStatisticsResponse>> getEventStatistics() {
    log.info("Received request to get event statistics");
    return ResponseEntity.ok(
        ApiResponseDTO.<EventStatisticsResponse>builder()
            .data(dashboardService.getEventStatistics())
            .message("Thống kê sự kiện đã được truy xuất thành công.")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }

  @GetMapping("/registrations")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  @Operation(
      summary = "Get event registration statistics",
      description = "Retrieves various statistics related to event registrations.")
  public ResponseEntity<ApiResponseDTO<EventRegistrationStatisticsResponse>>
      getEventRegistrationStatistics() {
    log.info("Received request to get event registration statistics");
    return ResponseEntity.ok(
        ApiResponseDTO.<EventRegistrationStatisticsResponse>builder()
            .data(dashboardService.getEventRegistrationStatistics())
            .message("Thống kê đăng ký sự kiện đã được truy xuất thành công.")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }

  @GetMapping("/staff")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  @Operation(
      summary = "Get event staff statistics",
      description = "Retrieves various statistics related to event staff.")
  public ResponseEntity<ApiResponseDTO<EventStaffStatisticsResponse>> getEventStaffStatistics() {
    log.info("Received request to get event staff statistics");
    return ResponseEntity.ok(
        ApiResponseDTO.<EventStaffStatisticsResponse>builder()
            .data(dashboardService.getEventStaffStatistics())
            .message("Thống kê nhân sự sự kiện đã được truy xuất thành công.")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }
}
