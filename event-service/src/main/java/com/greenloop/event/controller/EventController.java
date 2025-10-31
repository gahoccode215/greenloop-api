package com.greenloop.event.controller;

import com.greenloop.event.dto.request.EventRequest;
import com.greenloop.event.dto.response.ApiResponseDTO;
import com.greenloop.event.dto.response.EventDetailResponse;
import com.greenloop.event.dto.response.EventResponse;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.service.EventService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.time.LocalDateTime;
import java.util.Collection;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/events")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Event Controller", description = "Event API")
public class EventController {

  private final EventService eventService;

  /**
   * Create a new event with optional thumbnail image.
   *
   * @param request the event request data
   * @param multipartFile the optional thumbnail image file
   * @return ResponseEntity containing ApiResponseDTO with the ID of the created event
   */
  @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @Operation(
      summary = "Create Event",
      description = "Create a new event with optional thumbnail image")
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

  /**
   * Retrieve a list of events filtered by various criteria.
   *
   * @param page the page number (default is 0)
   * @param size the page size (default is 10)
   * @param code the event code to filter by (optional)
   * @param status the event status to filter by (optional)
   * @param search the search term to filter by (optional)
   * @param startTime the start time to filter by (optional)
   * @param endTime the end time to filter by (optional)
   * @param createdAtStart the creation start time to filter by (optional)
   * @param createdAtEnd the creation end time to filter by (optional)
   * @param sortBy the field to sort by (default is "createdAt")
   * @param sortDir the sort direction, either "ASC" or "DESC" (default is "DESC")
   * @return ResponseEntity containing ApiResponseDTO with a page of EventResponse
   */
  @GetMapping
  @Operation(summary = "Get events", description = "Retrieve a list of events")
  public ResponseEntity<ApiResponseDTO<Page<EventResponse>>> getEventByFilterByCustomer(
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
    log.info("Received request to get events by filter by customer: {}", code);
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Collection<? extends GrantedAuthority> roles = auth.getAuthorities();

    boolean isAdmin =
        roles.stream()
            .anyMatch(
                r ->
                    r.getAuthority().equals("ROLE_ADMIN")
                        || r.getAuthority().equals("ROLE_MANAGER")
                        || r.getAuthority().equals("ROLE_STAFF")
                        || r.getAuthority().equals("ROLE_STORE_MANAGER"));

    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
    Page<EventResponse> events =
        eventService.getEventsByFilterByCustomer(
            code,
            status,
            search,
            startTime,
            endTime,
            createdAtStart,
            createdAtEnd,
            pageable,
            isAdmin);
    log.info("Received events by filter by customer: {}", events.getSize());
    return ResponseEntity.ok(
        ApiResponseDTO.success("Events retrieved successfully", events, HttpStatus.OK));
  }

  /**
   * Retrieve event details by ID.
   *
   * @param id the ID of the event
   * @return ResponseEntity containing ApiResponseDTO with EventDetailResponse
   */
  @GetMapping("{id}")
  @Operation(summary = "Get event by ID", description = "Retrieve event details by ID")
  public ResponseEntity<ApiResponseDTO<EventDetailResponse>> getEventById(@PathVariable Long id) {
    log.info("Received request to get event by id: {}", id);
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Collection<? extends GrantedAuthority> roles = auth.getAuthorities();

    boolean isAdmin =
        roles.stream()
            .anyMatch(
                r ->
                    r.getAuthority().equals("ROLE_ADMIN")
                        || r.getAuthority().equals("ROLE_MANAGER")
                        || r.getAuthority().equals("ROLE_STAFF")
                        || r.getAuthority().equals("ROLE_STORE_MANAGER"));

    EventDetailResponse event = eventService.getEventByIdWithRole(id, isAdmin);

    log.info("Received event by id: {}", event);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Event retrieved successfully", event, HttpStatus.OK));
  }

  /**
   * Update an existing event by ID.
   *
   * @param id the ID of the event to update
   * @param request the updated event data
   * @return ResponseEntity containing ApiResponseDTO with the ID of the updated event
   */
  @PutMapping("/{id}")
  @Operation(summary = "Update Event", description = "Update an existing event by ID")
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> updateEvent(
      @PathVariable Long id, @RequestBody @Valid EventRequest request) {
    log.info("Received request to update event: {}", request);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(eventService.updateEvent(id, request))
            .message("Event updated successfully")
            .statusCode(HttpStatus.OK.value())
            .build());
  }

  /**
   * Activate an event by ID.
   *
   * @param id the ID of the event to activate
   * @return ResponseEntity containing ApiResponseDTO with the ID of the activated event
   */
  @PutMapping("{id}/activate")
  @Operation(summary = "Activate event", description = "Activate an event by ID")
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> activateEvent(@PathVariable Long id) {
    log.info("Received request to activate event with id: {}", id);
    Long activatedEventId = eventService.activateEvent(id);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(activatedEventId)
            .message("Event activated successfully")
            .statusCode(HttpStatus.OK.value())
            .build());
  }

  /**
   * Upload or update the thumbnail image for an existing event.
   *
   * @param id the ID of the event
   * @param multipartFile the thumbnail image file
   * @return ResponseEntity containing ApiResponseDTO with the ID of the event
   */
  @PutMapping(value = "/{id}/upload-thumbnail", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @Operation(
      summary = "Upload Event Thumbnail",
      description = "Upload or update the thumbnail image for an existing event")
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> uploadEventThumbnail(
      @PathVariable Long id, @RequestPart("thumbnail") MultipartFile multipartFile) {
    log.info("Received request to upload thumbnail for event id: {}", id);
    Long updatedEventId = eventService.uploadEventThumbnail(id, multipartFile);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(updatedEventId)
            .message("Event activated successfully")
            .statusCode(HttpStatus.OK.value())
            .build());
  }

  /**
   * Update the status of an existing event.
   *
   * @param id the ID of the event
   * @param status the new status for the event
   * @return ResponseEntity containing ApiResponseDTO with the ID of the updated event
   */
  @PutMapping("/{id}/status")
  @Operation(
      summary = "Update Event Status",
      description = "Update the status of an existing event")
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> updateEventStatus(
      @PathVariable Long id, @RequestParam EventStatus status) {
    log.info("Received request to update event status: {}", status);
    Long updatedEventId = eventService.updateEventStatus(id, status);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(updatedEventId)
            .message("Event status updated successfully")
            .statusCode(HttpStatus.OK.value())
            .build());
  }
}
