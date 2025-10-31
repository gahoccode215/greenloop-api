package com.greenloop.event.controller;

import com.greenloop.event.dto.request.UpdateRegistrationStatusRequest;
import com.greenloop.event.dto.response.ApiResponseDTO;
import com.greenloop.event.dto.response.EventUserRegistrationResponse;
import com.greenloop.event.dto.response.UserEventDetailResponse;
import com.greenloop.event.dto.response.UserEventResponse;
import com.greenloop.event.enums.RegistrationStatus;
import com.greenloop.event.service.EventRegistrationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
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

@RestController
@RequestMapping("/api/v1/event-registration")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Event Registration Controller", description = "Event Registration API")
public class EventRegistrationController {
  private final EventRegistrationService registrationService;

  /**
   * Register the current user to an event by its ID.
   *
   * @param eventId the ID of the event to register for
   * @return ResponseEntity with operation status
   */
  @PostMapping("/{eventId}/register")
  @PreAuthorize("hasRole('ROLE_CUSTOMER')")
  @Operation(
      summary = "Register to an event",
      description = "Allows a user to register for a specific event by its ID")
  public ResponseEntity<ApiResponseDTO<String>> registerToEvent(
      @PathVariable("eventId") Long eventId) {
    log.info("Received request to register to event {}", eventId);
    registrationService.registerUserToEvent(eventId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Registered successfully", "OK", HttpStatus.OK));
  }

  /**
   * Get a list of events the current user has registered for.
   *
   * @return ResponseEntity containing a list of user's registered events
   */
  @GetMapping("/my-events")
  @PreAuthorize("hasRole('ROLE_CUSTOMER')")
  @Operation(
      summary = "Get user's registered events",
      description = "Fetches a list of events the user has registered for")
  public ResponseEntity<ApiResponseDTO<List<UserEventResponse>>> getMyEvents() {
    log.info("Received request to get user's registered events");
    List<UserEventResponse> userEvents = registrationService.getUserRegisteredEvents();
    log.info("Received request to get user's registered events {}", userEvents);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Fetched user events successfully", userEvents, HttpStatus.OK));
  }

  /**
   * Get detailed information about a specific event the user has registered for.
   *
   * @param eventId the ID of the event
   * @return ResponseEntity containing detailed event information
   */
  @GetMapping("/my-events/{eventId}")
  @PreAuthorize("hasRole('ROLE_CUSTOMER')")
  @Operation(
      summary = "Get user's event detail",
      description =
          "Fetches detailed information about a specific event the user has registered for")
  public ResponseEntity<ApiResponseDTO<UserEventDetailResponse>> getMyEventDetail(
      @PathVariable Long eventId) {
    UserEventDetailResponse detail = registrationService.getUserEventDetail(eventId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Get event detail of user successfully", detail, HttpStatus.OK));
  }

  /**
   * Check-in a user by their ticket code.
   *
   * @param ticketCode the ticket code for check-in
   * @return ResponseEntity with operation status
   */
  @PostMapping("/check-in/{ticketCode}")
  @PreAuthorize("hasRole('ROLE_STAFF') or hasRole('ROLE_STORE_MANAGER')")
  @Operation(
      summary = "Check-in by ticket code",
      description = "Allows staff to check in a user using their ticket code")
  public ResponseEntity<ApiResponseDTO<String>> checkInByCode(@PathVariable String ticketCode) {
    registrationService.checkInByTicketCode(ticketCode);
    return ResponseEntity.ok(ApiResponseDTO.success("Check-in successful", "OK", HttpStatus.OK));
  }

  /**
   * Cancel the current user's registration for a specific event by its ID.
   *
   * @param eventId the ID of the event to cancel registration for
   * @return ResponseEntity with operation status
   */
  @PutMapping("/cancel/{eventId}")
  @PreAuthorize("hasRole('ROLE_CUSTOMER')")
  @Operation(
      summary = "Cancel event registration",
      description = "Allows a user to cancel their registration for a specific event by its ID")
  public ResponseEntity<ApiResponseDTO<String>> cancelEventRegistration(
      @PathVariable("eventId") Long eventId) {
    log.info("Received request to cancel registration for event {}", eventId);
    registrationService.cancelEventRegistration(eventId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Cancellation successful", "OK", HttpStatus.OK));
  }

  /**
   * Update a user's registration status for a specific event.
   *
   * @param eventId the ID of the event
   * @param request the request containing user ID and new registration status
   * @return ResponseEntity with operation status
   */
  @PutMapping("/admin/update-status/{eventId}")
  @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
  @Operation(
      summary = "Update user registration status",
      description = "Allows admin or manager to update a user's registration status for an event")
  public ResponseEntity<ApiResponseDTO<String>> updateRegistrationStatus(
      @PathVariable Long eventId, @RequestBody @Valid UpdateRegistrationStatusRequest request) {
    registrationService.updateRegistrationStatus(eventId, request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Registration status updated", "OK", HttpStatus.OK));
  }

  /**
   * Get registrations for a specific event, optionally filtered by registration status, with
   * pagination.
   *
   * @param eventId the ID of the event
   * @param status (optional) the registration status to filter by
   * @param page the page number for pagination (default is 0)
   * @param size the page size for pagination (default is 15)
   * @return ResponseEntity containing a paginated list of event user registrations
   */
  @GetMapping("/admin/event/{eventId}/registrations")
  @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
  @Operation(
      summary = "Get registrations for event (with optional status filter)",
      description =
          "Allows admin or manager to view registrations for a specific event, optionally filtered by registration status, with pagination")
  public ResponseEntity<ApiResponseDTO<Page<EventUserRegistrationResponse>>>
      getRegistrationsByEvent(
          @PathVariable Long eventId,
          @RequestParam(required = false) RegistrationStatus status,
          @RequestParam(defaultValue = "0") int page,
          @RequestParam(defaultValue = "15") int size) {

    Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

    Page<EventUserRegistrationResponse> registrations =
        registrationService.getRegistrationsByEvent(eventId, status, pageable);

    return ResponseEntity.ok(
        ApiResponseDTO.success("Registrations fetched", registrations, HttpStatus.OK));
  }
}
