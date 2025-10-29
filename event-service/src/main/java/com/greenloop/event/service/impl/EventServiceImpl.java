package com.greenloop.event.service.impl;

import com.greenloop.event.dto.request.EventRequest;
import com.greenloop.event.dto.response.EventDetailResponse;
import com.greenloop.event.dto.response.EventResponse;
import com.greenloop.event.dto.response.UserInfoResponse;
import com.greenloop.event.entity.Event;
import com.greenloop.event.enums.ErrorCode;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.exception.BusinessException;
import com.greenloop.event.repository.EventRepository;
import com.greenloop.event.service.CloudinaryService;
import com.greenloop.event.service.EventService;
import com.greenloop.event.service.UserServiceFeign;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
@RequiredArgsConstructor
@Slf4j
public class EventServiceImpl implements EventService {

  private final EventRepository eventRepository;
  private final CloudinaryService cloudinaryService;
  private final String localImagePath = "GreenLoop/Events";
  private UserServiceFeign userServiceFeign;

  /**
   * Creates a new event with the provided request data and optional thumbnail image. The event's
   * time range is validated to ensure the start time is before the end time, and both times are in
   * the future. If a thumbnail image is provided, it is uploaded to Cloudinary, and the event is
   * saved to the repository with a unique code generated based on the current date and time.
   *
   * @param request
   * @param multipartFile
   * @return
   */
  @Override
  public Long createEvent(EventRequest request, MultipartFile multipartFile) {
    Long userId =
        Long.valueOf(
            SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    log.info("Creating event with request: {} & user id {}", request, userId.toString());
    validateTimeRange(request.getStartTime(), request.getEndTime());
    Event event =
        Event.builder()
            .code(randomCode(request.getStartTime()))
            .description(request.getDescription())
            .startTime(request.getStartTime())
            .endTime(request.getEndTime())
            .name(request.getName())
            .note(request.getNote())
            .googlePlaceId(request.getGooglePlaceId())
            .latitude(request.getLatitude())
            .longitude(request.getLongitude())
            .status(EventStatus.CREATED)
            .locationDetail(request.getLocation())
            .build();

    if (multipartFile != null && !multipartFile.isEmpty()) {
      handleImageUpload(event, multipartFile);
    }
    log.info("Saving event to repository: {}", event);
    event.createdBy(userId);
    event = eventRepository.save(event);
    log.info("Event created successfully with ID: {}", event.getId());
    return event.getId();
  }

  /**
   * Retrieves a paginated list of events filtered by various criteria for customers. If the user is
   * not an admin, only events with status PUBLISHED, UPCOMING, or ONGOING and with a start time in
   * the future are returned.
   *
   * @param code The event code to filter by.
   * @param status The event status to filter by.
   * @param search A search term to filter event names.
   * @param startTime The start time to filter events from.
   * @param endTime The end time to filter events to.
   * @param createdAtStart The creation start time to filter events from.
   * @param createdAtEnd The creation end time to filter events to.
   * @param pageable The pagination information.
   * @param isAdmin Flag indicating if the user is an admin.
   * @return A paginated list of filtered event responses.
   */
  @Override
  public Page<EventResponse> getEventsByFilterByCustomer(
      String code,
      EventStatus status,
      String search,
      LocalDateTime startTime,
      LocalDateTime endTime,
      LocalDateTime createdAtStart,
      LocalDateTime createdAtEnd,
      Pageable pageable,
      boolean isAdmin) {
    Specification<Event> spec =
        (root, query, cb) -> {
          var predicates = cb.conjunction();

          if (code != null && !code.isEmpty()) {
            predicates = cb.and(predicates, cb.equal(root.get("code"), code));
          }

          if (status != null) {
            predicates = cb.and(predicates, cb.equal(root.get("status"), status));
          }

          if (!isAdmin) {
            predicates =
                cb.and(
                    predicates,
                    root.get("status")
                        .in(EventStatus.PUBLISHED, EventStatus.UPCOMING, EventStatus.ONGOING));
          }

          if (search != null && !search.isEmpty()) {
            String searchPattern = "%" + search.toLowerCase() + "%";
            predicates = cb.and(predicates, cb.like(cb.lower(root.get("name")), searchPattern));
          }

          if (startTime != null) {
            predicates =
                cb.and(predicates, cb.greaterThanOrEqualTo(root.get("startTime"), startTime));
          }

          if (endTime != null) {
            predicates = cb.and(predicates, cb.lessThanOrEqualTo(root.get("endTime"), endTime));
          }

          if (createdAtStart != null) {
            predicates =
                cb.and(predicates, cb.greaterThanOrEqualTo(root.get("createdAt"), createdAtStart));
          }

          if (createdAtEnd != null) {
            predicates =
                cb.and(predicates, cb.lessThanOrEqualTo(root.get("createdAt"), createdAtEnd));
          }

          if (!isAdmin) {
            predicates =
                cb.and(
                    predicates,
                    cb.greaterThanOrEqualTo(root.get("startTime"), LocalDateTime.now()));
          }

          return predicates;
        };

    return eventRepository.findAll(spec, pageable).map(this::fromEntity);
  }

  /**
   * Retrieves event details by ID, considering the user's role. If the user is not an admin, only
   * events with status PUBLISHED, UPCOMING, or ONGOING and with an end time in the future are
   * returned.
   *
   * @param id The ID of the event to retrieve.
   * @param isAdmin Flag indicating if the user is an admin.
   * @return The event details if accessible, otherwise null.
   */
  @Override
  public EventDetailResponse getEventByIdWithRole(Long id, boolean isAdmin) {
    Optional<Event> optionalEvent = eventRepository.findById(id);

    if (optionalEvent.isEmpty()) return null;

    Event event = optionalEvent.get();

    if (!isAdmin) {
      List<EventStatus> allowedStatuses =
          List.of(EventStatus.PUBLISHED, EventStatus.UPCOMING, EventStatus.ONGOING);

      if (!allowedStatuses.contains(event.getStatus())
          || event.getEndTime().isBefore(LocalDateTime.now())) {
        return null;
      }
    }

    return fromEntityToDetailResponse(event);
  }

  /**
   * Updates an existing event with the provided request data and optional thumbnail image. The
   * event's time range is validated to ensure the start time is before the end time, and both times
   * are in the future. If a thumbnail image is provided, it is uploaded to Cloudinary, replacing
   * any existing image. The event is then saved to the repository.
   *
   * @param id The ID of the event to update.
   * @param request The request data for updating the event.
   * @param multipartFile The optional thumbnail image file.
   * @return The ID of the updated event.
   * @throws BusinessException if the event is not found or if there are validation errors.
   */
  @Override
  public Long updateEvent(Long id, EventRequest request, MultipartFile multipartFile) {
    Long userId =
        Long.valueOf(
            SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    log.info("Updating event with id: {} & request: {} & user id {}", id, request, userId);
    Optional<Event> optionalEvent = eventRepository.findById(id);
    if (optionalEvent.isPresent()) {
      Event event = optionalEvent.get();
      validateTimeRange(
          request.getStartTime() != null ? request.getStartTime() : event.getStartTime(),
          request.getEndTime() != null ? request.getEndTime() : event.getEndTime());

      event.setName(request.getName() != null ? request.getName() : event.getName());
      event.setDescription(
          request.getDescription() != null ? request.getDescription() : event.getDescription());
      event.setStartTime(
          request.getStartTime() != null ? request.getStartTime() : event.getStartTime());
      event.setEndTime(request.getEndTime() != null ? request.getEndTime() : event.getEndTime());
      event.setLocationDetail(
          request.getLocation() != null ? request.getLocation() : event.getLocationDetail());
      event.setGooglePlaceId(
          request.getGooglePlaceId() != null
              ? request.getGooglePlaceId()
              : event.getGooglePlaceId());
      event.setLatitude(
          request.getLatitude() != null ? request.getLatitude() : event.getLatitude());
      event.setLongitude(
          request.getLongitude() != null ? request.getLongitude() : event.getLongitude());
      event.setStatus(request.getStatus() != null ? request.getStatus() : event.getStatus());
      event.setNote(request.getNote() != null ? request.getNote() : event.getNote());

      if (multipartFile != null && !multipartFile.isEmpty()) {
        handleImageUpload(event, multipartFile);
      }

      event.updatedBy(userId);
      eventRepository.save(event);
      log.info("Event updated successfully with ID: {}", event.getId());
      return event.getId();
    }
    throw new BusinessException(ErrorCode.EVENT_NOT_FOUND);
  }

  /**
   * Toggles the activation status of an event by its ID. If the event is found, its activation
   * status is flipped (active to inactive or vice versa), and the event is updated with the user ID
   * of the person making the change.
   *
   * @param id The ID of the event to activate/deactivate.
   * @return The ID of the event if found and updated, otherwise null.
   */
  @Override
  public Long activateEvent(Long id) {
    Long userId =
        Long.valueOf(
            SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    log.info("Activating event with id: {}", id);

    Optional<Event> optionalEvent = eventRepository.findById(id);
    if (optionalEvent.isPresent()) {
      Event event = optionalEvent.get();

      event.activate(!event.isActive());
      event.updatedBy(userId);
      eventRepository.save(event);
      log.info("Event activation status changed successfully for ID: {}", event.getId());
      return event.getId();
    }
    return null;
  }

  private EventDetailResponse fromEntityToDetailResponse(Event event) {
    UserInfoResponse creatorInfo = null;
    UserInfoResponse updaterInfo = null;

    if (event.getCreatedBy() != null) {
      creatorInfo = userServiceFeign.getUserInfoById(event.getCreatedBy());
    }

    if (event.getUpdatedBy() != null) {
      if (creatorInfo == null || !event.getUpdatedBy().equals(creatorInfo.getId())) {
        updaterInfo = userServiceFeign.getUserInfoById(event.getUpdatedBy());
      } else {
        updaterInfo = creatorInfo;
      }
    }

    return EventDetailResponse.builder()
        .id(event.getId())
        .code(event.getCode())
        .name(event.getName())
        .description(event.getDescription())
        .imageUrl(event.getImageUrl())
        .locationDetail(event.getLocationDetail())
        .latitude(event.getLatitude())
        .longitude(event.getLongitude())
        .startTime(event.getStartTime())
        .endTime(event.getEndTime())
        .status(event.getStatus())
        .googlePlaceId(event.getGooglePlaceId())
        .totalRegistrations(event.getRegistrations() != null ? event.getRegistrations().size() : 0)
        .totalStaffs(event.getStaffAssignments() != null ? event.getStaffAssignments().size() : 0)
        .isActive(event.isActive())
        .createdBy(event.getCreatedBy())
        .createByName(creatorInfo != null ? creatorInfo.getFullName() : null)
        .createdAt(event.getCreatedAt())
        .updatedAt(event.getUpdatedAt())
        .updatedBy(event.getUpdatedBy())
        .updatedByName(updaterInfo != null ? updaterInfo.getFullName() : null)
        .build();
  }

  private EventResponse fromEntity(Event event) {
    return EventResponse.builder()
        .id(event.getId())
        .code(event.getCode())
        .name(event.getName())
        .startTime(event.getStartTime())
        .endTime(event.getEndTime())
        .status(event.getStatus())
        .build();
  }

  /**
   * Generates a random event code in the format "EV_ddMMyy_ss". - "EV" is a static prefix. -
   * "ddMMyy" is the current date in day, month, year format. - "ss" is the current second, padded
   * to two digits.
   *
   * @return A unique event code.
   */
  // Example: EV_010123_45 for an event created on January 1,
  private String randomCode(LocalDateTime startTime) {
    LocalDateTime now = LocalDateTime.now();
    String datePart = startTime.format(DateTimeFormatter.ofPattern("ddMMyy"));
    String secondPart = String.format("%06d", now.getSecond());
    return "EV_" + datePart + "_" + secondPart;
  }

  /**
   * Handles the image upload for an event. If the event already has an image, it deletes the old
   * image from Cloudinary. Then, it uploads the new image and updates the event with the new image
   * URL and media key.
   *
   * @param event The event to update with the new image.
   * @param file The image file to upload.
   */
  private void handleImageUpload(Event event, MultipartFile file) {
    try {
      if (event.getMediaKey() != null) {
        cloudinaryService.deleteImage(event.getMediaKey());
      }
      Map<String, String> accessKey =
          this.cloudinaryService.uploadImage(file.getBytes(), localImagePath);
      event.updateImage(
          cloudinaryService.getImageUrl(accessKey.get("asset_id")), accessKey.get("public_id"));
    } catch (Exception e) {
      log.error("Error while uploading cinema image: {}", e.getMessage(), e);
      throw new BusinessException(ErrorCode.UPLOAD_IMAGE_ERROR);
    }
  }

  /**
   * Validates the time range for an event. - Ensures the start time is before the end time. -
   * Ensures the start time is not in the past. - Ensures the end time is not in the past.
   *
   * @param startTime The start time of the event.
   * @param endTime The end time of the event.
   */
  private void validateTimeRange(LocalDateTime startTime, LocalDateTime endTime) {
    if (startTime.isAfter(endTime)) {
      throw new BusinessException(ErrorCode.EVENT_END_TIME_BEFORE_START);
    }
    if (startTime.isBefore(LocalDateTime.now())) {
      throw new BusinessException(ErrorCode.EVENT_START_TIME_PAST);
    }
    if (endTime.isBefore(LocalDateTime.now())) {
      throw new BusinessException(ErrorCode.EVENT_END_TIME_PAST);
    }
  }
}
