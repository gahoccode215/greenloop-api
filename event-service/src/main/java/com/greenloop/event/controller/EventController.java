package com.greenloop.event.controller;

import com.greenloop.event.dto.request.*;
import com.greenloop.event.dto.response.*;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.enums.RegistrationStatus;
import com.greenloop.event.service.EventService;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/events")
@RequiredArgsConstructor
@Slf4j
public class EventController {

  private final EventService eventService;

  // --------------------------- Event CRUD ---------------------------

  @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @Operation(
      summary = "Create Event",
      description = "Create a new event with optional thumbnail image",
      tags = {"Event CRUD"})
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> createEvent(
      @RequestPart("event") @Valid EventRequest request,
      @RequestPart(value = "thumbnail", required = false) MultipartFile multipartFile) {
    log.info("Received request to create event: {}", request);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(eventService.createEvent(request, multipartFile))
            .message("Event created successfully")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }

  @GetMapping("/customers")
  @Operation(
      summary = "Get Events by Filter (CUSTOMER)",
      description = "Retrieve a list of events filtered by code, status, date, or search query",
      tags = {"Event CRUD"})
  public ResponseEntity<ApiResponseDTO<Page<EventResponse>>> getEventsByFilter(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @RequestParam(required = false) String code,
      @RequestParam(required = false) EventStatus status,
      @RequestParam(required = false) String search,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime startTime,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime endTime,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime createdAtStart,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime createdAtEnd,
      @RequestParam(defaultValue = "createdAt") String sortBy,
      @RequestParam(defaultValue = "DESC") String sortDir) {

    log.info("Received request to get events by filter: {}", code);

    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
    Page<EventResponse> events =
        eventService.getEventsForCustomer(
            code, status, search, startTime, endTime, createdAtStart, createdAtEnd, pageable);

    return ResponseEntity.ok(
        ApiResponseDTO.success("Events retrieved successfully", events, HttpStatus.OK));
  }

  @GetMapping("/admin")
  @Operation(
      summary = "Get Events by Filter (ADMIN)",
      description = "Retrieve a list of events filtered by code, status, date, or search",
      tags = {"Event CRUD"})
  @PreAuthorize(
      "hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_STAFF') or hasRole('ROLE_STORE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<Page<EventResponse>>> getEventsByFilterForAdmin(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @RequestParam(required = false) String code,
      @RequestParam(required = false) EventStatus status,
      @RequestParam(required = false) String search,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime startTime,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime endTime,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime createdAtStart,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime createdAtEnd,
      @RequestParam(defaultValue = "createdAt") String sortBy,
      @RequestParam(defaultValue = "DESC") String sortDir) {
    log.info("Received request to get events by filter for admin: {}", code);
    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
    Page<EventResponse> events =
        eventService.getEventsForAdmin(
            code, status, search, startTime, endTime, createdAtStart, createdAtEnd, pageable);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Events retrieved successfully", events, HttpStatus.OK));
  }

  @GetMapping("/customers/{id}")
  @Operation(
      summary = "Get Event by ID (CUSTOMER)",
      description = "Retrieve event details by ID for customers",
      tags = {"Event CRUD"})
  public ResponseEntity<ApiResponseDTO<EventDetailResponse>> getEventById(@PathVariable Long id) {
    log.info("Received request to get event by id: {}", id);

    EventDetailResponse event = eventService.getEventByIdForCustomer(id);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Event retrieved successfully", event, HttpStatus.OK));
  }

  @GetMapping("/admin/{id}")
  @Operation(
      summary = "Get Event by ID (ADMIN)",
      description = "Retrieve event details by ID for admins",
      tags = {"Event CRUD"})
  @PreAuthorize(
      "hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_STAFF') or hasRole('ROLE_STORE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<EventDetailResponse>> getEventByIdForAdmin(
      @PathVariable Long id) {
    log.info("Received request to get event by id for admin: {}", id);
    EventDetailResponse event = eventService.getEventByIdForAdmin(id);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Event retrieved successfully", event, HttpStatus.OK));
  }

  @PutMapping("/{id}")
  @Operation(
      summary = "Update Event",
      description = "Update an existing event by ID",
      tags = {"Event CRUD"})
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> updateEvent(
      @PathVariable Long id, @RequestBody EventUpdateRequest request) {
    log.info("Updating event {}", id);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(eventService.updateEvent(id, request))
            .message("Event updated successfully")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }

  @PutMapping("/{id}/status")
  @Operation(
      summary = "Update Event Status",
      description = "Update the status of an existing event",
      tags = {"Event CRUD"})
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> updateEventStatus(
      @PathVariable Long id, @RequestParam EventStatus status) {
    log.info("Updating event {} status to {}", id, status);
    Long updatedEventId = eventService.updateEventStatus(id, status);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(updatedEventId)
            .message("Event status updated successfully")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }

  @PutMapping("/{id}/activate")
  @Operation(
      summary = "Activate Event",
      description = "Activate an existing event",
      tags = {"Event CRUD"})
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> activateEvent(@PathVariable Long id) {
    Long activatedId = eventService.activateEvent(id);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(activatedId)
            .message("Event activated successfully")
            .statusCode(HttpStatus.OK.value())
            .build());
  }

  @PutMapping(value = "/{id}/thumbnail", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @Operation(
      summary = "Upload Event Thumbnail",
      description = "Upload or update thumbnail for an event",
      tags = {"Event CRUD"})
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> uploadEventThumbnail(
      @PathVariable Long id, @RequestPart("thumbnail") MultipartFile multipartFile) {
    Long updatedId = eventService.uploadEventThumbnail(id, multipartFile);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(updatedId)
            .message("Event thumbnail uploaded successfully")
            .statusCode(HttpStatus.OK.value())
            .build());
  }

  // --------------------------- Event Staff ---------------------------

  @PostMapping("/staffs")
  @Operation(
      summary = "Assign Staffs to Event",
      description = "Assign multiple staff members to an event",
      tags = {"Event Staff Management"})
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Void>> assignStaffList(
      @RequestBody @Valid AssignStaffListRequest request) {
    eventService.assignStaffToEvent(request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Staff assigned to event successfully", null, HttpStatus.OK));
  }

  @PutMapping("/{eventId}/staffs")
  @Operation(
      summary = "Update Staff Assignments",
      description = "Update staff assignments for a specific event",
      tags = {"Event Staff Management"})
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Void>> updateStaffAssignments(
      @PathVariable Long eventId, @RequestBody @Valid AssignStaffListRequest request) {
    eventService.updateStaffAssignments(eventId, request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Staff assignments updated successfully", null, HttpStatus.OK));
  }

  @GetMapping("/{eventId}/staffs")
  @Operation(
      summary = "Get Staffs by Event",
      description = "Retrieve list of staff assigned to a specific event",
      tags = {"Event Staff Management"})
  @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN','ROLE_STAFF','ROLE_CUSTOMER')")
  public ResponseEntity<ApiResponseDTO<List<EventStaffResponse>>> getStaffsByEventId(
      @PathVariable Long eventId) {
    List<EventStaffResponse> staffs = eventService.getStaffs(eventId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Staffs retrieved successfully", staffs, HttpStatus.OK));
  }

  // --------------------------- Event Registration ---------------------------

  @PostMapping("/{eventId}/register")
  @Operation(
      summary = "Register to Event",
      description = "Register the current user for an event",
      tags = {"Event Registration"})
  @PreAuthorize("hasRole('ROLE_CUSTOMER')")
  public ResponseEntity<ApiResponseDTO<String>> registerToEvent(
      @PathVariable Long eventId, @RequestBody RegisterEventRequest request) {
    eventService.registerUserToEvent(eventId, request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Registered successfully", "OK", HttpStatus.OK));
  }

  @GetMapping("/my-events")
  @Operation(
      summary = "Get My Events",
      description = "Retrieve a list of events registered by the current user",
      tags = {"Event Registration"})
  @PreAuthorize("hasRole('ROLE_CUSTOMER')")
  public ResponseEntity<ApiResponseDTO<List<UserEventResponse>>> getMyEvents() {
    List<UserEventResponse> events = eventService.getUserRegisteredEvents();
    return ResponseEntity.ok(
        ApiResponseDTO.success("User events retrieved successfully", events, HttpStatus.OK));
  }

  @GetMapping("/my-events/{registerId}")
  @Operation(
      summary = "Get My Event Detail",
      description = "Retrieve detailed info for a registered event",
      tags = {"Event Registration"})
  @PreAuthorize("hasRole('ROLE_CUSTOMER')")
  public ResponseEntity<ApiResponseDTO<UserEventDetailResponse>> getMyEventDetail(
      @PathVariable Long registerId) {
    UserEventDetailResponse detail = eventService.getUserEventDetail(registerId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Event detail retrieved successfully", detail, HttpStatus.OK));
  }

  @PutMapping("/{eventId}/cancel")
  @Operation(
      summary = "Cancel Event Registration",
      description = "Cancel user's event registration",
      tags = {"Event Registration"})
  @PreAuthorize("hasRole('ROLE_CUSTOMER')")
  public ResponseEntity<ApiResponseDTO<String>> cancelEventRegistration(
      @PathVariable Long eventId) {
    eventService.cancelEventRegistration(eventId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Registration cancelled successfully", "OK", HttpStatus.OK));
  }

  @PostMapping("/check-in/{ticketCode}")
  @Operation(
      summary = "Check-in by Ticket",
      description = "Check-in attendee by ticket code",
      tags = {"Event Registration"})
  @PreAuthorize("hasAnyRole('ROLE_STAFF','ROLE_STORE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<String>> checkInByCode(@PathVariable String ticketCode) {
    eventService.checkInByTicketCode(ticketCode);
    return ResponseEntity.ok(ApiResponseDTO.success("Check-in successful", "OK", HttpStatus.OK));
  }

  @GetMapping("/{ticketCode}/user-registration")
  @Operation(
      summary = "Get User Registration by Ticket Code",
      description =
          "Retrieve user registration details using ticket code by staff, store manager, manager, or admin",
      tags = {"Event Registration"})
  @PreAuthorize("hasAnyRole('ROLE_STAFF','ROLE_STORE_MANAGER', 'ROLE_MANAGER','ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<EventUserRegistrationResponse>>
      getUserRegistrationByTicketCode(@PathVariable String ticketCode) {
    EventUserRegistrationResponse registration =
        eventService.getUserRegistrationByTicketCode(ticketCode);
    return ResponseEntity.ok(
        ApiResponseDTO.success(
            "User registration retrieved successfully", registration, HttpStatus.OK));
  }

  // --------------------------- Event Admin ---------------------------

  @PutMapping("/admin/{eventId}/status")
  @Operation(
      summary = "Update Registration Status",
      description = "Update user's registration status for an event",
      tags = {"Event Administration"})
  @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<String>> updateRegistrationStatus(
      @PathVariable Long eventId, @RequestBody @Valid UpdateRegistrationStatusRequest request) {
    eventService.updateRegistrationStatus(eventId, request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Registration status updated", "OK", HttpStatus.OK));
  }

  @GetMapping("/admin/{eventId}/registrations")
  @Operation(
      summary = "Get Event Registrations",
      description = "Retrieve registrations for a specific event with optional filtering",
      tags = {"Event Administration"})
  @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<Page<EventUserRegistrationResponse>>>
      getRegistrationsByEvent(
          @PathVariable Long eventId,
          @RequestParam(required = false) RegistrationStatus status,
          @RequestParam(defaultValue = "0") int page,
          @RequestParam(defaultValue = "15") int size) {

    Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
    Page<EventUserRegistrationResponse> registrations =
        eventService.getRegistrationsByEvent(eventId, status, pageable);

    return ResponseEntity.ok(
        ApiResponseDTO.success(
            "Registrations retrieved successfully", registrations, HttpStatus.OK));
  }

  // --------------------------- Event Staff Schedule ---------------------------
  @GetMapping("/staffs/schedule")
  @Operation(
      summary = "Get Staff Event Schedule",
      description = "Retrieve the event schedule for the current staff member",
      tags = {"Event Staff Management"})
  @PreAuthorize("hasAnyRole('ROLE_STAFF')")
  public ResponseEntity<ApiResponseDTO<List<EventStaffScheduleResponse>>> getStaffEventSchedule() {
    List<EventStaffScheduleResponse> schedules = eventService.getStaffSchedules();
    return ResponseEntity.ok(
        ApiResponseDTO.success("Staff schedules retrieved successfully", schedules, HttpStatus.OK));
  }

  // --------------------------- Internal APIs ---------------------------

  @Hidden
  @GetMapping("/internal/{eventId}/staff/{staffId}/validate")
  public ResponseEntity<Boolean> validateStaffInEvent(
      @PathVariable Long eventId,
      @PathVariable Long staffId,
      @RequestHeader(value = "API_SECRET_HEADER", required = false) String apiSecret) {
    if (!"greenloopsecret".equals(apiSecret)) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    boolean isValid = eventService.validateStaffInEvent(eventId, staffId);
    return ResponseEntity.ok(isValid);
  }

  @Hidden
  @GetMapping("/internal/{eventId}/info")
  public ResponseEntity<EventResponse> getInfoEventId(
      @PathVariable Long eventId,
      @RequestHeader(value = "API_SECRET_HEADER", required = false) String apiSecret) {
    if (!"greenloopsecret".equals(apiSecret)) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    EventResponse eventResponse = eventService.getInfoEvent(eventId);
    return ResponseEntity.ok(eventResponse);
  }
}
