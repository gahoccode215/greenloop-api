package com.greenloop.event.controller;

import com.greenloop.event.dto.request.EventRequest;
import com.greenloop.event.dto.response.ApiResponseDTO;
import com.greenloop.event.dto.response.EventDetailResponse;
import com.greenloop.event.dto.response.EventResponse;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.service.EventService;
import com.greenloop.event.utils.ErrorResponseUtils;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1")
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
  public ResponseEntity<ApiResponseDTO<Long>> createEvent(
      @RequestPart("event") @Valid EventRequest request,
      @RequestPart(value = "thumbnail", required = false) MultipartFile multipartFile) {
    log.info("Received request to create event: {}", request);

    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(eventService.createEvent(request, multipartFile))
            .message("Event created successfully")
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

    boolean isAdmin = roles.stream().anyMatch(r -> r.getAuthority().equals("ROLE_ADMIN"));

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

    boolean isAdmin = roles.stream().anyMatch(r -> r.getAuthority().equals("ROLE_ADMIN"));
    EventDetailResponse event = eventService.getEventByIdWithRole(id, isAdmin);

    if (event == null) {
      return ErrorResponseUtils.buildNotFoundResponse(
          "Event not found or access denied", "/api/v1/events/" + id);
    }

    log.info("Received event by id: {}", event);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Event retrieved successfully", event, HttpStatus.OK));
  }

  /**
   * Update an existing event with optional thumbnail image.
   *
   * @param id the ID of the event to update
   * @param request the event request data
   * @param multipartFile the optional thumbnail image file
   * @return ResponseEntity containing ApiResponseDTO with the ID of the updated event
   */
  @PutMapping("/{id}")
  @Operation(
      summary = "Update Event",
      description = "Update an existing event with optional thumbnail image")
  public ResponseEntity<ApiResponseDTO<Long>> updateEvent(
      @PathVariable Long id,
      @RequestPart("event") @RequestBody @Valid EventRequest request,
      @RequestPart(value = "thumbnail", required = false) MultipartFile multipartFile) {
    log.info("Received request to update event: {}", request);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(eventService.updateEvent(id, request, multipartFile))
            .message("Event updated successfully")
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
  public ResponseEntity<ApiResponseDTO<Long>> activateEvent(@PathVariable Long id) {
    log.info("Received request to activate event with id: {}", id);
    Long activatedEventId = eventService.activateEvent(id);
    if (activatedEventId == null) {
      return ErrorResponseUtils.buildNotFoundResponse(
          "Event not found or already active", "/api/v1/events/" + id + "/activate");
    }
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(activatedEventId)
            .message("Event activated successfully")
            .build());
  }
}
