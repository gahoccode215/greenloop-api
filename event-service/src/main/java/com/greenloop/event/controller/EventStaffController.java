package com.greenloop.event.controller;

import com.greenloop.event.dto.request.AssignStaffListRequest;
import com.greenloop.event.dto.response.ApiResponseDTO;
import com.greenloop.event.dto.response.EventStaffResponse;
import com.greenloop.event.service.EventStaffService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/event-staff")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Event Staff Controller", description = "Event API")
public class EventStaffController {

  private final EventStaffService eventStaffService;

  /**
   * Assign staff members to an event.
   *
   * @param request the request containing event ID and staff assignments
   * @return ResponseEntity with operation status
   */
  @PostMapping
  @PreAuthorize("hasRole('MANAGER') or hasRole('ADMIN')")
  @Operation(
      summary = "Assign staff list to event",
      description = "Assign multiple staff to an event, including one store manager")
  public ResponseEntity<ApiResponseDTO<Void>> assignStaffList(
      @RequestBody @Valid AssignStaffListRequest request) {
    log.info("Assign staff list to event");
    eventStaffService.assignStaffToEvent(request);
    return ResponseEntity.ok(
        ApiResponseDTO.<Void>builder()
            .statusCode(HttpStatus.OK.value())
            .message("Staff assigned to event successfully")
            .build());
  }

  /**
   * Update staff assignments for an event.
   *
   * @param eventId the ID of the event
   * @param request the request containing updated staff assignments
   * @return ResponseEntity with operation status
   */
  @PutMapping("/{eventId}")
  @PreAuthorize("hasRole('MANAGER') or hasRole('ADMIN')")
  @Operation(
      summary = "Update staff assignments for an event",
      description = "Update the list of staff assigned to a specific event")
  public ResponseEntity<ApiResponseDTO<Void>> updateStaffAssignments(
      @PathVariable Long eventId, @RequestBody @Valid AssignStaffListRequest request) {
    log.info("Update staff assignments for event {}", eventId);
    eventStaffService.updateStaffAssignments(eventId, request);
    return ResponseEntity.ok(
        ApiResponseDTO.<Void>builder()
            .statusCode(HttpStatus.OK.value())
            .message("Staff assignments updated successfully")
            .build());
  }

  /**
   * Get staff members assigned to an event.
   *
   * @param eventId the ID of the event
   * @return ResponseEntity containing the list of assigned staff members
   */
  @GetMapping("/{eventId}/staffs")
  @PreAuthorize("hasRole('MANAGER') or hasRole('ADMIN') or hasRole('STAFF') or hasRole('CUSTOMER')")
  @Operation(
      summary = "Get staff assigned to an event",
      description = "Retrieve the list of staff members assigned to a specific event")
  public ResponseEntity<ApiResponseDTO<List<EventStaffResponse>>> getStaffsByEventId(
      @PathVariable Long eventId) {
    log.info("Get staff assigned to event {}", eventId);
    List<EventStaffResponse> staffs = eventStaffService.getStaffs(eventId);
    return ResponseEntity.ok(
        ApiResponseDTO.<List<EventStaffResponse>>builder()
            .statusCode(HttpStatus.OK.value())
            .message("Staffs retrieved successfully")
            .data(staffs)
            .build());
  }
}
