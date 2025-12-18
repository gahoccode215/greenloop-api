package com.greenloop.event.service.impl;

import com.greenloop.event.constraint.RoleConstants;
import com.greenloop.event.dto.event.NotificationEvent;
import com.greenloop.event.dto.request.*;
import com.greenloop.event.dto.response.*;
import com.greenloop.event.entity.Event;
import com.greenloop.event.entity.EventRegistration;
import com.greenloop.event.entity.EventStaffAssignment;
import com.greenloop.event.enums.*;
import com.greenloop.event.exception.BusinessException;
import com.greenloop.event.repository.EventRegistrationRepository;
import com.greenloop.event.repository.EventRepository;
import com.greenloop.event.repository.EventStaffAssignmentRepository;
import com.greenloop.event.service.*;
import jakarta.transaction.Transactional;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
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
  private final EventRegistrationRepository registrationRepository;
  private final EventStaffAssignmentRepository assignmentRepository;
  private final CloudinaryService cloudinaryService;
  private final String localImagePath = "GreenLoop/Events";
  private final UserServiceFeign userServiceFeign;
  private final EcoPointCheckInProducer ecoPointCheckInProducer;
  private final NotificationProducer notificationProducer;
  private final RewardServiceFeign rewardServiceFeign;

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
    log.info("Creating event with request: {} & user id {}", request, userId);
    validateTimeRange(request.getStartTime(), request.getEndTime());
    Event event =
        Event.builder()
            .code(randomCodeEventCode(request.getStartTime()))
            .description(request.getDescription())
            .startTime(request.getStartTime())
            .endTime(request.getEndTime())
            .name(request.getName())
            .note(request.getNote())
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
   * Retrieves a paginated list of events for customers based on various filters such as code,
   * status, search term, time range, and creation date range. Only public events with specific
   * statuses and active status are included in the results. The method also checks if the current
   * user is registered for each event.
   *
   * @param code The event code to filter by.
   * @param status The event status to filter by.
   * @param search A search term to filter by event name.
   * @param startTime The start time to filter events.
   * @param endTime The end time to filter events.
   * @param createdAtStart The start of the creation date range to filter events.
   * @param createdAtEnd The end of the creation date range to filter events.
   * @param pageable The pagination information.
   * @return A paginated list of event responses for customers.
   */
  @Override
  public Page<EventResponse> getEventsForCustomer(
      String code,
      EventStatus status,
      String search,
      LocalDateTime startTime,
      LocalDateTime endTime,
      LocalDateTime createdAtStart,
      LocalDateTime createdAtEnd,
      Pageable pageable) {

    Specification<Event> spec =
        (root, query, cb) -> {
          var predicates = cb.conjunction();

          if (code != null && !code.isEmpty()) {
            predicates = cb.and(predicates, cb.equal(root.get("code"), code));
          }

          if (status != null) {
            predicates = cb.and(predicates, cb.equal(root.get("status"), status));
          }

          predicates =
              cb.and(
                  predicates,
                  root.get("status")
                      .in(EventStatus.PUBLISHED, EventStatus.UPCOMING, EventStatus.ONGOING),
                  cb.isTrue(root.get("isActive")),
                  cb.greaterThanOrEqualTo(root.get("endTime"), LocalDateTime.now()));

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

          return predicates;
        };

    Page<Event> events = eventRepository.findAll(spec, pageable);

    List<Long> registeredEventIds = Collections.emptyList();
    try {
      Long currentUserId = getCurrentUserId();
      if (currentUserId != null) {
        registeredEventIds =
            registrationRepository.findByUserIdAndIsActiveTrue(currentUserId).stream()
                .map(reg -> reg.getEvent().getId())
                .toList();
      }
    } catch (Exception e) {
      log.debug("No authenticated user, skipping registration filter");
    }
    final List<Long> finalRegisteredEventIds = registeredEventIds;

    return events.map(
        event ->
            EventResponse.builder()
                .id(event.getId())
                .code(event.getCode())
                .name(event.getName())
                .location(event.getLocationDetail())
                .startTime(event.getStartTime())
                .endTime(event.getEndTime())
                .totalParticipants(event.getRegistrations().size())
                .totalStaffs(event.getStaffAssignments().size())
                .imageUrl(event.getImageUrl())
                .status(event.getStatus())
                .latitude(event.getLatitude())
                .longitude(event.getLongitude())
                .isRegistered(finalRegisteredEventIds.contains(event.getId()))
                .isActive(event.isActive())
                .build());
  }

  /**
   * Retrieves a paginated list of events for admin users based on various filters such as code,
   * status, search term, time range, and creation date range.
   */
  @Override
  public Page<EventResponse> getEventsForAdmin(
      String code,
      EventStatus status,
      String search,
      LocalDateTime startTime,
      LocalDateTime endTime,
      LocalDateTime createdAtStart,
      LocalDateTime createdAtEnd,
      Pageable pageable) {

    Specification<Event> spec =
        (root, query, cb) -> {
          var predicates = cb.conjunction();

          if (code != null && !code.isEmpty()) {
            predicates = cb.and(predicates, cb.equal(root.get("code"), code));
          }

          if (status != null) {
            predicates = cb.and(predicates, cb.equal(root.get("status"), status));
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

          return predicates;
        };

    Page<Event> events = eventRepository.findAll(spec, pageable);

    return events.map(
        event ->
            EventResponse.builder()
                .id(event.getId())
                .code(event.getCode())
                .name(event.getName())
                .location(event.getLocationDetail())
                .startTime(event.getStartTime())
                .endTime(event.getEndTime())
                .imageUrl(event.getImageUrl())
                .totalParticipants(event.getRegistrations().size())
                .totalStaffs(event.getStaffAssignments().size())
                .status(event.getStatus())
                .latitude(event.getLatitude())
                .longitude(event.getLongitude())
                .isActive(event.isActive())
                .build());
  }

  /**
   * Retrieves detailed information about an event by its ID for admin users.
   *
   * @param id The ID of the event to retrieve.
   * @return The detailed response of the event.
   * @throws BusinessException if the event is not found.
   */
  @Override
  public EventDetailResponse getEventByIdForAdmin(Long id) {
    Event event =
        eventRepository
            .findById(id)
            .orElseThrow(
                () ->
                    new BusinessException(
                        "Không tìm thấy sự kiện với ID: " + id, ErrorCode.EVENT_NOT_FOUND));

    return fromEntityToDetailResponse(event, false);
  }

  /**
   * Retrieves detailed information about an event by its ID for customers. Only events with
   * specific statuses and that have not ended are accessible.
   *
   * @param id The ID of the event to retrieve.
   * @return The detailed response of the event.
   * @throws BusinessException if the event is not found or not accessible to customers.
   */
  @Override
  public EventDetailResponse getEventByIdForCustomer(Long id) {
    Event event =
        eventRepository
            .findById(id)
            .orElseThrow(
                () ->
                    new BusinessException(
                        "Không tìm thấy sự kiện với ID: " + id, ErrorCode.EVENT_NOT_FOUND));

    List<EventStatus> allowedStatuses =
        List.of(EventStatus.PUBLISHED, EventStatus.UPCOMING, EventStatus.ONGOING);

    if (!allowedStatuses.contains(event.getStatus())
        || event.getEndTime().isBefore(LocalDateTime.now())) {
      throw new BusinessException(
          "Không tìm thấy sự kiện với ID: " + id, ErrorCode.EVENT_NOT_FOUND);
    }

    boolean isRegistered = false;
    try {
      Long currentUserId = getCurrentUserId();
      if (currentUserId != null) {
        isRegistered =
            registrationRepository.existsByEventIdAndUserIdAndIsActiveTrue(id, currentUserId);
      }
    } catch (Exception e) {
      log.debug("No authenticated user, skipping registration check");
    }
    return fromEntityToDetailResponse(event, isRegistered);
  }

  /**
   * Updates an existing event with the provided request data. The event's time range is validated
   * to ensure the start time is before the end time, and both times are in the future. Only the
   * fields provided in the request are updated; others remain unchanged.
   *
   * @param id The ID of the event to update.
   * @param request The request data containing updated event information.
   * @return The ID of the updated event.
   */
  @Override
  public Long updateEvent(Long id, EventUpdateRequest request) {
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
      event.setLatitude(
          request.getLatitude() != null ? request.getLatitude() : event.getLatitude());
      event.setLongitude(
          request.getLongitude() != null ? request.getLongitude() : event.getLongitude());
      event.setStatus(request.getStatus() != null ? request.getStatus() : event.getStatus());
      event.setNote(request.getNote() != null ? request.getNote() : event.getNote());

      event.updatedBy(userId);
      eventRepository.save(event);
      log.info("Event updated successfully with ID: {}", event.getId());
      return event.getId();
    }
    throw new BusinessException("Không tìm thấy sự kiện với ID: " + id, ErrorCode.EVENT_NOT_FOUND);
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
    throw new BusinessException("Không tìm thấy sự kiện với ID: " + id, ErrorCode.EVENT_NOT_FOUND);
  }

  /**
   * Uploads a thumbnail image for an event by its ID. If the event is found, the provided image
   * file is uploaded to Cloudinary, replacing any existing image associated with the event. The
   * event is then updated with the new image URL and media key.
   *
   * @param id The ID of the event to upload the thumbnail for.
   * @param multipartFile The image file to upload as the thumbnail.
   * @return The ID of the event if found and updated, otherwise null.
   */
  @Override
  public Long uploadEventThumbnail(Long id, MultipartFile multipartFile) {
    Long userId =
        Long.valueOf(
            SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    log.info("Uploading thumbnail for event with id: {}", id);
    Optional<Event> optionalEvent = eventRepository.findById(id);
    if (optionalEvent.isPresent()) {
      Event event = optionalEvent.get();

      handleImageUpload(event, multipartFile);

      event.updatedBy(userId);
      eventRepository.save(event);
      log.info("Event thumbnail uploaded successfully for ID: {}", event.getId());
      return event.getId();
    }
    throw new BusinessException("Không tìm thấy sự kiện với ID: " + id, ErrorCode.EVENT_NOT_FOUND);
  }

  /**
   * Updates the status of an event based on its ID and the desired new status. The method validates
   * the status transition according to predefined rules:
   *
   * <ul>
   *   <li>CREATED, PUBLISHED, UPCOMING: Start time must be in the future.
   *   <li>ONGOING: Current time must be between start and end times.
   *   <li>CLOSED: End time must be in the past.
   *   <li>CANCELED: Always allowed.
   * </ul>
   *
   * <p>If the status transition is valid, the event's status is updated, and the event is saved to
   * the repository.
   *
   * @param id The ID of the event to update.
   * @param status The new status to set for the event.
   * @return The ID of the updated event.
   * @throws BusinessException if the event is not found or if the status transition is invalid.
   */
  @Override
  public Long updateEventStatus(Long id, EventStatus status) {
    Long userId =
        Long.valueOf(
            SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    log.info("Updating status for event with id: {} to status: {}", id, status);

    Event event =
        eventRepository
            .findById(id)
            .orElseThrow(
                () ->
                    new BusinessException(
                        "Không tìm thấy sự kiện với ID: " + id, ErrorCode.EVENT_NOT_FOUND));

    LocalDateTime now = LocalDateTime.now();
    LocalDateTime start = event.getStartTime();
    LocalDateTime end = event.getEndTime();

    switch (status) {
      case CREATED, PUBLISHED, UPCOMING -> {
        if (start.isBefore(now)) {
          throw new BusinessException(ErrorCode.INVALID_EVENT_STATUS);
        }
      }
      case ONGOING -> {
        if (start.isAfter(now) || end.isBefore(now)) {
          throw new BusinessException(ErrorCode.INVALID_EVENT_STATUS);
        }
      }
      case CLOSED -> {
        if (end.isAfter(now)) {
          throw new BusinessException(ErrorCode.INVALID_EVENT_STATUS);
        }
      }
      case CANCELED -> {
        // always allowed
      }
      default ->
          throw new BusinessException(
              "Trạng thái sự kiện không hợp lệ", ErrorCode.INVALID_EVENT_STATUS);
    }

    event.setStatus(status);
    event.updatedBy(userId);
    eventRepository.save(event);
    log.info("Event status updated successfully for ID: {}", event.getId());

    if (status == EventStatus.CLOSED) {
      List<Long> notifiedUserIds = new ArrayList<>();
      notifiedUserIds.addAll(
          event.getStaffAssignments().stream().map(EventStaffAssignment::getStaffId).toList());
      notifiedUserIds.addAll(
          event.getRegistrations().stream().map(EventRegistration::getUserId).toList());
      for (Long userIdToNotify : notifiedUserIds) {
        notificationProducer.sendNotificationMessage(
            NotificationEvent.builder()
                .userId(userIdToNotify)
                .title("Sự kiện đã kết thúc")
                .message(
                    "Sự kiện "
                        + event.getName()
                        + " đã chính thức kết thúc. Cảm ơn bạn đã tham gia!")
                .build());
      }
    }
    if (status == EventStatus.CANCELED) {
      List<Long> notifiedUserIds = new ArrayList<>();
      notifiedUserIds.addAll(
          event.getStaffAssignments().stream().map(EventStaffAssignment::getStaffId).toList());
      notifiedUserIds.addAll(
          event.getRegistrations().stream().map(EventRegistration::getUserId).toList());
      for (Long userIdToNotify : notifiedUserIds) {
        notificationProducer.sendNotificationMessage(
            NotificationEvent.builder()
                .userId(userIdToNotify)
                .title("Sự kiện đã bị hủy")
                .message(
                    "Sự kiện "
                        + event.getName()
                        + " đã bị hủy bỏ. Chúng tôi xin lỗi vì sự bất tiện này.")
                .build());
      }
    }

      if (status == EventStatus.UPCOMING
              || status == EventStatus.ONGOING
              || status == EventStatus.PUBLISHED) {

          List<Long> notifiedUserIds = new ArrayList<>();
//          notifiedUserIds.addAll(
//                  event.getStaffAssignments().stream()
//                          .map(EventStaffAssignment::getStaffId)
//                          .toList()
//          );
//          notifiedUserIds.addAll(
//                  event.getRegistrations().stream()
//                          .map(EventRegistration::getUserId)
//                          .toList()
//          );
          try {
              notifiedUserIds = userServiceFeign.getAllUserIds();
          } catch (Exception e) {
                log.error("Failed to fetch all user IDs for notifications: {}", e.getMessage());
          }

          String title = "";
          String message = "";

          switch (status) {
              case UPCOMING -> {
                  title = "Sự kiện sắp diễn ra";
                  message = "Sự kiện " + event.getName()
                          + " sẽ diễn ra vào ngày "
                          + event.getStartTime().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm"))
                          + ". Hãy chuẩn bị tham gia nhé!";
              }
              case ONGOING -> {
                  title = "Sự kiện đang diễn ra";
                  message = "Sự kiện " + event.getName()
                          + " hiện đang diễn ra. Hãy tham gia ngay để không bỏ lỡ!";
              }
              case PUBLISHED -> {
                  title = "Sự kiện đã được công bố";
                  message = "Sự kiện " + event.getName()
                          + " đã chính thức được công bố. Hãy theo dõi để không bỏ lỡ!";
              }
              default -> {
              }
          }

          for (Long idU : notifiedUserIds) {
              notificationProducer.sendNotificationMessage(
                      NotificationEvent.builder()
                              .userId(idU)
                              .title(title)
                              .message(message)
                              .build()
              );
          }
      }


      return event.getId();
  }

  private EventDetailResponse fromEntityToDetailResponse(Event event, boolean isRegistered) {

    UserProfileResponse creatorInfo = null;
    UserProfileResponse updaterInfo = null;

    try {
      if (event.getCreatedBy() != null) {
        creatorInfo = userServiceFeign.getUserInfoById(event.getCreatedBy());
      }
    } catch (Exception e) {
      log.error(
          "Failed to get creator info for userId {}: {}", event.getCreatedBy(), e.getMessage());
    }

    try {
      if (event.getUpdatedBy() != null) {
        if (creatorInfo == null || !event.getUpdatedBy().equals(creatorInfo.getUserId())) {
          try {
            updaterInfo = userServiceFeign.getUserInfoById(event.getUpdatedBy());
          } catch (Exception e) {
            log.error(
                "Failed to get updater info for userId {}: {}",
                event.getUpdatedBy(),
                e.getMessage());
          }
        } else {
          updaterInfo = creatorInfo;
        }
      }
    } catch (Exception e) {
      log.error("Unexpected error when fetching updater info: {}", e.getMessage());
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
        .isRegistered(isRegistered)
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

  /**
   * Generates a random event code in the format "EV_ddMMyy_ss". - "EV" is a static prefix. -
   * "ddMMyy" is the current date in day, month, year format. - "ss" is the current second, padded
   * to two digits.
   *
   * @return A unique event code.
   */
  // Example: EV_010123_45 for an event created on January 1,
  private String randomCodeEventCode(LocalDateTime startTime) {
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
   * Assign staff members to an event.
   *
   * @param request the request containing event ID and staff assignments
   * @throws BusinessException if the event is not found, user not found, staff already assigned,
   *     invalid role, or store manager already assigned
   */
  @Override
  @Transactional
  public void assignStaffToEvent(AssignStaffListRequest request) {
    Long currentUserId =
        Long.valueOf(
            SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    log.info("User {} is assigning staff to event {}", currentUserId, request.getEventId());
    Event event =
        eventRepository
            .findById(request.getEventId())
            .orElseThrow(
                () ->
                    new BusinessException(
                        "Không tìm thấy sự kiện với ID: " + request.getEventId(),
                        ErrorCode.EVENT_NOT_FOUND));

    boolean hasStoreManager =
        assignmentRepository.existsByEventIdAndIsStoreManagerTrue(event.getId());
    List<EventStaffAssignment> assignments = new ArrayList<>();

    for (AssignStaffListRequest.StaffAssignmentDTO dto : request.getStaffAssignments()) {
      UserProfileResponse user = userServiceFeign.getUserInfoById(dto.getStaffId());
      if (user == null || Boolean.FALSE.equals(user.getIsActive())) {
        throw new BusinessException(
            "Không tìm thấy người dùng hoặc người dùng chưa kích hoạt", ErrorCode.USER_NOT_FOUND);
      }

      if (assignmentRepository.existsByEventIdAndStaffId(event.getId(), dto.getStaffId())) {
        throw new BusinessException(
            "Nhân viên đã được phân công cho sự kiện này", ErrorCode.STAFF_ALREADY_ASSIGNED);
      }

      List<Event> assignedEvents = assignmentRepository.findEventsByStaffId(dto.getStaffId());
      for (Event assignedEvent : assignedEvents) {
        boolean overlap =
            !(event.getEndTime().isBefore(assignedEvent.getStartTime())
                || event.getStartTime().isAfter(assignedEvent.getEndTime()));
        if (overlap) {
          throw new BusinessException(
              "Nhân viên có sự kiện khác trùng thời gian với sự kiện này",
              ErrorCode.STAFF_EVENT_TIME_CONFLICT);
        }
      }

      if (dto.isStoreManager()) {
        if (hasStoreManager) {
          throw new BusinessException(
              "Đã có quản lý cửa hàng được phân công cho sự kiện này",
              ErrorCode.STORE_MANAGER_ALREADY_ASSIGNED);
        }
        hasStoreManager = true;
      } else {
        if (!user.getRoles().contains(RoleConstants.STAFF)) {
          throw new BusinessException("Người dùng không có vai trò hợp lệ", ErrorCode.INVALID_ROLE);
        }
      }

      EventStaffAssignment assignment =
          EventStaffAssignment.builder()
              .event(event)
              .staffId(dto.getStaffId())
              .isStoreManager(dto.isStoreManager())
              .build();
      assignment.createdBy(currentUserId);
      assignments.add(assignment);
    }
    assignmentRepository.saveAll(assignments);
    for (AssignStaffListRequest.StaffAssignmentDTO dto : request.getStaffAssignments()) {
      notificationProducer.sendNotificationMessage(
          NotificationEvent.builder()
              .userId(dto.getStaffId())
              .title("Phân công công việc")
              .message(
                  "Bạn đã được phân công làm "
                      + (dto.isStoreManager() ? "quản lý cửa hàng " : "nhân viên ")
                      + "cho sự kiện: "
                      + event.getName())
              .build());
    }
    log.info(
        "User {} successfully assigned staff to event {}", currentUserId, request.getEventId());
  }

  /**
   * Update staff assignments for an event.
   *
   * @param eventId the ID of the event
   * @param request the request containing updated staff assignments
   * @throws BusinessException if the event is not found or store manager already assigned
   */
  @Transactional
  @Override
  public void updateStaffAssignments(Long eventId, AssignStaffListRequest request) {
    Long currentUserId =
        Long.valueOf(
            SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    log.info("User {} is updating staff assignments for event {}", currentUserId, eventId);

    Event event =
        eventRepository
            .findById(eventId)
            .orElseThrow(
                () ->
                    new BusinessException(
                        "Không tìm thấy sự kiện với ID: " + eventId, ErrorCode.EVENT_NOT_FOUND));

    List<EventStaffAssignment> currentAssignments =
        assignmentRepository.findByEventIdAndIsActiveTrue(eventId);

    Map<Long, Boolean> newAssignments =
        request.getStaffAssignments().stream()
            .collect(
                Collectors.toMap(
                    AssignStaffListRequest.StaffAssignmentDTO::getStaffId,
                    AssignStaffListRequest.StaffAssignmentDTO::isStoreManager));

    // --- DELETE ---
    List<EventStaffAssignment> toDelete =
        currentAssignments.stream()
            .filter(a -> !newAssignments.containsKey(a.getStaffId()))
            .collect(Collectors.toList());
    assignmentRepository.deleteAll(toDelete);

    // --- ADD ---
    Set<Long> currentStaffIds =
        currentAssignments.stream()
            .map(EventStaffAssignment::getStaffId)
            .collect(Collectors.toSet());

    List<EventStaffAssignment> toAdd =
        newAssignments.entrySet().stream()
            .filter(e -> !currentStaffIds.contains(e.getKey()))
            .map(
                e -> {
                  // validate user
                  UserProfileResponse user = userServiceFeign.getUserInfoById(e.getKey());
                  if (user == null || Boolean.FALSE.equals(user.getIsActive())) {
                    throw new BusinessException(
                        "Không tìm thấy người dùng hoặc người dùng chưa kích hoạt",
                        ErrorCode.USER_NOT_FOUND);
                  }

                  // validate trùng lịch
                  List<Event> assignedEvents = assignmentRepository.findEventsByStaffId(e.getKey());
                  for (Event assignedEvent : assignedEvents) {
                    boolean overlap =
                        !(event.getEndTime().isBefore(assignedEvent.getStartTime())
                            || event.getStartTime().isAfter(assignedEvent.getEndTime()));
                    if (overlap && !assignedEvent.getId().equals(eventId)) {
                      throw new BusinessException(
                          "Nhân viên có sự kiện khác trùng thời gian với sự kiện này",
                          ErrorCode.STAFF_EVENT_TIME_CONFLICT);
                    }
                  }

                  return EventStaffAssignment.builder()
                      .event(event)
                      .staffId(e.getKey())
                      .isStoreManager(e.getValue())
                      .build();
                })
            .toList();
    assignmentRepository.saveAll(toAdd);

    // --- UPDATE ---
    List<EventStaffAssignment> toUpdate =
        currentAssignments.stream()
            .filter(a -> newAssignments.containsKey(a.getStaffId()))
            .filter(a -> a.isStoreManager() != newAssignments.get(a.getStaffId()))
            .peek(
                a -> {
                  a.setStoreManager(newAssignments.get(a.getStaffId()));
                  a.updatedBy(currentUserId);
                })
            .toList();

    assignmentRepository.saveAll(toUpdate);

    // --- VALIDATION ---
    long storeManagerCount =
        assignmentRepository.findByEventIdAndIsActiveTrue(eventId).stream()
            .filter(EventStaffAssignment::isStoreManager)
            .count();

    if (storeManagerCount > 1) {
      throw new BusinessException(ErrorCode.STORE_MANAGER_ALREADY_ASSIGNED);
    }
    for (AssignStaffListRequest.StaffAssignmentDTO dto : request.getStaffAssignments()) {
      notificationProducer.sendNotificationMessage(
          NotificationEvent.builder()
              .userId(dto.getStaffId())
              .title("Cập nhật phân công công việc")
              .message(
                  "Phân công của bạn đã được cập nhật cho sự kiện: "
                      + event.getName()
                      + ". Vai trò mới của bạn là "
                      + (dto.isStoreManager() ? "quản lý cửa hàng " : "nhân viên "))
              .build());
    }
    log.info("User {} successfully updated staff assignments for event {}", currentUserId, eventId);
  }

  /**
   * Get the list of staff assigned to an event.
   *
   * @param eventId the ID of the event
   * @return the list of staff assigned to the event
   */
  @Override
  public List<EventStaffResponse> getStaffs(Long eventId) {
    List<EventStaffAssignment> assignments = assignmentRepository.findByEventId(eventId);

    return assignments.stream()
        .map(
            assignment -> {
              UserProfileResponse user = userServiceFeign.getUserInfoById(assignment.getStaffId());

              return EventStaffResponse.builder()
                  .staffId(assignment.getStaffId())
                  .fullName(user != null ? user.getFullName() : null)
                  .email(user != null ? user.getEmail() : null)
                  .isStoreManager(assignment.isStoreManager())
                  .isActive(assignment.isActive())
                  .createdAt(assignment.getCreatedAt())
                  .updatedAt(assignment.getUpdatedAt())
                  .build();
            })
        .toList();
  }

  /**
   * Registers the current user to an event specified by eventId. Generates a unique QR code for the
   * registration.
   *
   * @param eventId the ID of the event to register for
   * @throws BusinessException if the event is not found or the user is already registered
   */
  @Override
  public void registerUserToEvent(Long eventId, RegisterEventRequest request) {
    Long userId = getCurrentUserId();
    log.info("Registering user {} to event {}", userId, eventId);

    Event event =
        eventRepository
            .findById(eventId)
            .orElseThrow(
                () -> {
                  log.warn("Event {} not found for registration by user {}", eventId, userId);
                  return new BusinessException(ErrorCode.EVENT_NOT_FOUND);
                });

    if (event.getStatus() == EventStatus.CREATED
        || event.getStatus() == EventStatus.CLOSED
        || event.getStatus() == EventStatus.CANCELED) {
      throw new BusinessException(
          "Sự kiện không mở đăng ký (status: " + event.getStatus() + ")",
          ErrorCode.INVALID_EVENT_STATUS);
    }

    Optional<EventRegistration> existingRegistrationOpt =
        registrationRepository.findByEventIdAndUserId(eventId, userId);

    if (existingRegistrationOpt.isPresent()) {
      EventRegistration existingRegistration = existingRegistrationOpt.get();
      if (existingRegistration.isActive()) {
        log.warn("User {} is already registered to event {}", userId, eventId);
        throw new BusinessException(
            "Người dùng đã đăng ký sự kiện này", ErrorCode.ALREADY_REGISTERED);
      } else {
        String qrCode = randomCodeCustomerCode(event.getStartTime());
        existingRegistration.setActive(true);
        existingRegistration.setQrCode(qrCode);
        existingRegistration.setStatus(RegistrationStatus.BOOKED);
        existingRegistration.setNote(request.getNote());
        existingRegistration.updatedBy(userId);
        registrationRepository.save(existingRegistration);
        log.info("User {} re-registered to event {} with QR code {}", userId, eventId, qrCode);
        return;
      }
    }
    String qrCode = randomCodeCustomerCode(event.getStartTime());
    EventRegistration registration =
        EventRegistration.builder()
            .qrCode(qrCode)
            .event(event)
            .userId(userId)
            .status(RegistrationStatus.BOOKED)
            .note(request.getNote())
            .build();
    registration.createdBy(userId);
    registrationRepository.save(registration);
    log.info(
        "User {} successfully registered to event {} with QR code {}", userId, eventId, qrCode);
  }

  /**
   * Checks in a user using their ticket code (QR code). Updates the registration status to ATTENDED
   * and records the check-in time.
   *
   * @param ticketCode the QR code of the ticket
   * @throws BusinessException if no active registration is found for the user with the given ticket
   *     code
   */
  @Override
  public void checkInByTicketCode(String ticketCode) {
    Long userId = getCurrentUserId();
    log.info("Checking in staff {} with ticket code {}", userId, ticketCode);

    EventRegistration registration =
        registrationRepository
            .findByQrCodeAndIsActiveTrue(ticketCode)
            .orElseThrow(
                () -> {
                  log.warn(
                      "Không tìm thấy đăng ký hoạt động cho user {} với mã vé {}",
                      userId,
                      ticketCode);
                  return new BusinessException(
                      "Không tìm thấy đăng ký sự kiện với mã vé: " + ticketCode,
                      ErrorCode.REGISTRATION_NOT_FOUND);
                });

    Event event = registration.getEvent();
    LocalDateTime now = LocalDateTime.now();

    if (now.isBefore(event.getStartTime())) {
      log.warn(
          "User {} attempted to check in before event start time. Event starts at {}",
          userId,
          event.getStartTime());
      throw new BusinessException(
          "Sự kiện chưa bắt đầu. Thời gian bắt đầu: " + event.getStartTime(),
          ErrorCode.EVENT_NOT_STARTED);
    }

    registration.setStatus(RegistrationStatus.ATTENDED);
    registration.setCheckinTime(now);
    registration.updatedBy(userId);
    registrationRepository.save(registration);
    EcoPointTransactionDTO ecoPointTransaction =
        EcoPointTransactionDTO.builder()
            .userId(registration.getUserId())
            .points(5)
            .description("Eco points for Checkin code: " + ticketCode)
            .sourceType(SourceType.EVENT)
            .sourceId(registration.getId())
            .type(EcoPointType.EARNED)
            .build();

    try {
        Boolean result = rewardServiceFeign.updateEcoPoints(ecoPointTransaction);
        if (result == null || !result) {
            ecoPointCheckInProducer.sendEcoPointDonationMessage(ecoPointTransaction);
        }
        log.info("Eco points updated successfully via Reward Service for user {}", registration.getUserId());
    } catch (Exception e) {
        ecoPointCheckInProducer.sendEcoPointDonationMessage(ecoPointTransaction);
        log.info("Failed to update eco points via Reward Service, queued for retry: {}", e.getMessage());
    }

    notificationProducer.sendNotificationMessage(
        NotificationEvent.builder()
            .userId(registration.getUserId())
            .title("Check-in sự kiện thành công")
            .message(
                "Bạn đã check-in thành công cho sự kiện: "
                    + event.getName()
                    + ". Bạn nhận được 5 điểm Eco Point.")
            .build());

    log.info("User {} successfully checked in with ticket code {}", userId, ticketCode);
  }

  /**
   * Cancels the event registration for the current user for a specific event.
   *
   * @param eventId the ID of the event to cancel registration for
   * @throws BusinessException if no active registration is found for the user and event
   */
  @Override
  public void cancelEventRegistration(Long eventId) {
    Long userId = getCurrentUserId();
    log.info("Cancelling registration for user {} to event {}", userId, eventId);
    EventRegistration registration =
        registrationRepository
            .findByEventIdAndUserIdAndIsActiveTrue(eventId, userId)
            .orElseThrow(
                () -> {
                  log.warn(
                      "Không tìm thấy đăng ký hoạt động cho user {} và sự kiện {}",
                      userId,
                      eventId);
                  return new BusinessException(
                      "Không tìm thấy đăng ký sự kiện cho User ID: "
                          + userId
                          + ", Event ID: "
                          + eventId,
                      ErrorCode.REGISTRATION_NOT_FOUND);
                });

    registration.setActive(false);
    registration.setStatus(RegistrationStatus.CANCELED);
    registration.updatedBy(userId);
    registrationRepository.save(registration);
    log.info("User {} successfully cancelled registration to event {}", userId, eventId);
    notificationProducer.sendNotificationMessage(
        NotificationEvent.builder()
            .userId(userId)
            .title("Hủy đăng ký sự kiện thành công")
            .message("Bạn đã hủy đăng ký thành công cho sự kiện ID: " + eventId)
            .build()
    );
  }

  /**
   * Updates the registration status for a specific user and event.
   *
   * @param eventId the ID of the event
   * @param updateRegistrationStatusRequest the request containing user ID and new registration
   *     status
   * @throws BusinessException if no active registration is found for the user and event
   */
  @Override
  public void updateRegistrationStatus(
      Long eventId, UpdateRegistrationStatusRequest updateRegistrationStatusRequest) {
    Long currentUserId = getCurrentUserId();
    log.info(
        "Updating registration status for user {} to event {}",
        updateRegistrationStatusRequest.getUserId(),
        eventId);
    EventRegistration registration =
        registrationRepository
            .findByEventIdAndUserId(eventId, updateRegistrationStatusRequest.getUserId())
            .orElseThrow(
                () -> {
                  log.warn(
                      "Không tìm thấy đăng ký cho user {} và sự kiện {}",
                      updateRegistrationStatusRequest.getUserId(),
                      eventId);
                  return new BusinessException(
                      "Không tìm thấy đăng ký sự kiện cho User ID: "
                          + updateRegistrationStatusRequest.getUserId()
                          + ", Event ID: "
                          + eventId,
                      ErrorCode.REGISTRATION_NOT_FOUND);
                });

    registration.setStatus(updateRegistrationStatusRequest.getRegistrationStatus());
    registration.updatedBy(currentUserId);
    registrationRepository.save(registration);
    log.info(
        "Successfully updated registration status for user {} to event {}",
        updateRegistrationStatusRequest.getUserId(),
        eventId);
  }

  /**
   * Retrieves a list of events the current user has registered for.
   *
   * @return a list of UserEventResponse containing the user's registered events
   */
  @Override
  public List<UserEventResponse> getUserRegisteredEvents() {
    Long userId = getCurrentUserId();
    log.info("Fetching registered events for user {}", userId);
    List<EventRegistration> registrations = registrationRepository.findByUserId(userId);
    return registrations.stream()
        .map(
            reg -> {
              Event event = reg.getEvent();
              return UserEventResponse.builder()
                  .registerId(reg.getId())
                  .eventId(event.getId())
                  .eventName(event.getName())
                  .eventCode(event.getCode())
                  .imageUrl(event.getImageUrl())
                  .startTime(event.getStartTime())
                  .endTime(event.getEndTime())
                  .registrationStatus(reg.getStatus())
                  .build();
            })
        .toList();
  }

  /**
   * Retrieves detailed information about a user's event registration by registration ID.
   *
   * @param registrationId the ID of the event registration
   * @return a UserEventDetailResponse containing detailed information about the registration
   * @throws BusinessException if no registration is found for the given ID
   */
  @Override
  public UserEventDetailResponse getUserEventDetail(Long registrationId) {
    log.info("Fetching event registration detail for registration ID {}", registrationId);
    Long currentUserId = getCurrentUserId();
    EventRegistration registration =
        registrationRepository
            .findById(registrationId)
            .orElseThrow(
                () -> {
                  log.warn("Không tìm thấy đăng ký với ID {}", registrationId);
                  return new BusinessException(
                      "Không tìm thấy đăng ký sự kiện với ID: " + registrationId,
                      ErrorCode.REGISTRATION_NOT_FOUND);
                });

    if (!registration.getUserId().equals(currentUserId)) {
      log.warn(
          "User {} is not authorized to access registration ID {}", currentUserId, registrationId);
      throw new BusinessException(ErrorCode.UNAUTHORIZED_ACCESS);
    }
    Event event = registration.getEvent();
    return UserEventDetailResponse.builder()
        .registerId(registration.getId())
        .eventId(event.getId())
        .registrationId(registration.getId())
        .ticketCode(registration.getQrCode())
        .eventCode(event.getCode())
        .eventName(event.getName())
        .location(event.getLocationDetail())
        .startTime(event.getStartTime())
        .endTime(event.getEndTime())
        .imageUrl(event.getImageUrl())
        .latitude(event.getLatitude())
        .longitude(event.getLongitude())
        .checkInTime(registration.getCheckinTime())
        .registrationStatus(registration.getStatus())
        .isActive(registration.isActive())
        .build();
  }

  /**
   * Retrieves a paginated list of user registrations for a specific event, optionally filtered by
   * registration status.
   *
   * @param eventId the ID of the event
   * @param status the registration status to filter by (optional)
   * @param pageable the pagination information
   * @return a paginated list of EventUserRegistrationResponse containing user registrations
   */
  @Override
  public Page<EventUserRegistrationResponse> getRegistrationsByEvent(
      Long eventId, RegistrationStatus status, Pageable pageable) {
    Page<EventRegistration> registrations;

    if (status != null) {
      registrations = registrationRepository.findByEventIdAndStatus(eventId, status, pageable);
    } else {
      registrations = registrationRepository.findByEventId(eventId, pageable);
    }

    return registrations.map(
        reg -> {
          UserProfileResponse user = userServiceFeign.getUserInfoById(reg.getUserId());
          return EventUserRegistrationResponse.builder()
              .userId(reg.getUserId())
              .fullName(user != null ? user.getFullName() : null)
              .email(user != null ? user.getEmail() : null)
              .registrationStatus(reg.getStatus())
              .checkInTime(reg.getCheckinTime())
              .isActive(reg.isActive())
              .createdAt(reg.getCreatedAt())
              .note(reg.getNote())
              .build();
        });
  }

  @Override
  public Boolean validateStaffInEvent(Long eventId, Long staffId) {
    EventStaffAssignment assignment =
        assignmentRepository.findByEventIdAndStaffIdAndIsActiveTrue(eventId, staffId);
    if (assignment != null) {
      return true;
    }
    return false;
  }

  @Override
  public List<EventStaffScheduleResponse> getStaffSchedules() {

    Long staffId = getCurrentUserId();

    List<EventStaffAssignment> staffAssignment =
        assignmentRepository.findByStaffIdAndIsActiveTrue(staffId);
    if (staffAssignment != null && !staffAssignment.isEmpty()) {
      return staffAssignment.stream()
          .map(
              assignment -> {
                Event event = assignment.getEvent();
                return EventStaffScheduleResponse.builder()
                    .staffId(assignment.getStaffId())
                    .isStoreManager(assignment.isStoreManager())
                    .eventId(event.getId())
                    .code(event.getCode())
                    .name(event.getName())
                    .location(event.getLocationDetail())
                    .imageUrl(event.getImageUrl())
                    .startTime(event.getStartTime())
                    .endTime(event.getEndTime())
                    .status(event.getStatus())
                    .latitude(event.getLatitude())
                    .longitude(event.getLongitude())
                    .build();
              })
          .toList();
    }
    return List.of();
  }

  @Override
  public EventUserRegistrationResponse getUserRegistrationByTicketCode(String ticketCode) {
    EventRegistration registration =
        registrationRepository
            .findByQrCodeAndIsActiveTrue(ticketCode)
            .orElseThrow(
                () -> {
                  log.warn("Không tìm thấy đăng ký hoạt động với mã vé {}", ticketCode);
                  return new BusinessException(
                      "Không tìm thấy đăng ký sự kiện với mã vé: " + ticketCode,
                      ErrorCode.REGISTRATION_NOT_FOUND);
                });

    UserProfileResponse user = null;
    try {
      user = userServiceFeign.getUserInfoById(registration.getUserId());

    } catch (Exception e) {
      log.error(
          "Failed to get user info for userId {}: {}", registration.getUserId(), e.getMessage());
    }
    return EventUserRegistrationResponse.builder()
        .userId(registration.getUserId())
        .fullName(user.getFullName() != null ? user.getFullName() : null)
        .email(user.getEmail() != null ? user.getEmail() : null)
        .registrationStatus(registration.getStatus())
        .checkInTime(registration.getCheckinTime())
        .isActive(registration.isActive())
        .createdAt(registration.getCreatedAt())
        .note(registration.getNote())
        .build();
  }

  @Override
  public EventResponse getInfoEvent(Long eventId) {
    Event event =
        eventRepository
            .findById(eventId)
            .orElseThrow(
                () ->
                    new BusinessException(
                        "Không tìm thấy sự kiện với ID: " + eventId, ErrorCode.EVENT_NOT_FOUND));

    return EventResponse.builder()
        .id(event.getId())
        .code(event.getCode())
        .name(event.getName())
        .location(event.getLocationDetail())
        .startTime(event.getStartTime())
        .endTime(event.getEndTime())
        .imageUrl(event.getImageUrl())
        .status(event.getStatus())
        .latitude(event.getLatitude())
        .longitude(event.getLongitude())
        .isActive(event.isActive())
        .build();
  }

  private Long getCurrentUserId() {
    return Long.valueOf(
        SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
  }

  private String randomCodeCustomerCode(LocalDateTime startTime) {
    LocalDateTime now = LocalDateTime.now();
    String datePart = startTime.format(DateTimeFormatter.ofPattern("ddMMyy"));
    String secondPart = String.format("%06d", now.getSecond());
    return "CS_" + datePart + "_" + secondPart;
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
      throw new BusinessException(
          "Thời gian kết thúc của sự kiện không được trước thời gian bắt đầu",
          ErrorCode.EVENT_END_TIME_BEFORE_START);
    }
    if (startTime.isBefore(LocalDateTime.now())) {
      throw new BusinessException(
          "Thời gian bắt đầu của sự kiện không được ở quá khứ", ErrorCode.EVENT_START_TIME_PAST);
    }
    if (endTime.isBefore(LocalDateTime.now())) {
      throw new BusinessException(
          "Thời gian kết thúc của sự kiện không được ở quá khứ", ErrorCode.EVENT_END_TIME_PAST);
    }
  }
}
