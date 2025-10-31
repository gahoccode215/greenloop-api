package com.greenloop.event.service.impl;

import com.greenloop.event.dto.request.UpdateRegistrationStatusRequest;
import com.greenloop.event.dto.response.EventUserRegistrationResponse;
import com.greenloop.event.dto.response.UserEventDetailResponse;
import com.greenloop.event.dto.response.UserEventResponse;
import com.greenloop.event.dto.response.UserProfileResponse;
import com.greenloop.event.entity.Event;
import com.greenloop.event.entity.EventRegistration;
import com.greenloop.event.enums.ErrorCode;
import com.greenloop.event.enums.RegistrationStatus;
import com.greenloop.event.exception.BusinessException;
import com.greenloop.event.repository.EventRegistrationRepository;
import com.greenloop.event.repository.EventRepository;
import com.greenloop.event.service.EventRegistrationService;
import com.greenloop.event.service.UserServiceFeign;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EventRegistrationServiceImpl implements EventRegistrationService {
  private final EventRegistrationRepository registrationRepository;
  private final EventRepository eventRepository;
  private final UserServiceFeign userServiceFeign;

  /**
   * Registers the current user to an event specified by eventId. Generates a unique QR code for the
   * registration.
   *
   * @param eventId the ID of the event to register for
   * @throws BusinessException if the event is not found or the user is already registered
   */
  @Override
  public void registerUserToEvent(Long eventId) {
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
    boolean alreadyRegistered =
        registrationRepository.existsByEventIdAndUserIdAndIsActiveTrue(eventId, userId);
    if (alreadyRegistered) {
      log.warn("User {} is already registered to event {}", userId, eventId);
      throw new BusinessException(ErrorCode.ALREADY_REGISTERED);
    }
    String qrCode = randomCode(event.getStartTime());
    EventRegistration registration =
        EventRegistration.builder()
            .qrCode(qrCode)
            .event(event)
            .userId(userId)
            .status(RegistrationStatus.BOOKED)
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
    log.info("Checking in user {} with ticket code {}", userId, ticketCode);
    EventRegistration registration =
        registrationRepository
            .findByQrCodeAndUserIdAndIsActiveTrue(ticketCode, userId)
            .orElseThrow(
                () -> {
                  log.warn(
                      "No active registration found for user {} with ticket code {}",
                      userId,
                      ticketCode);
                  return new BusinessException(ErrorCode.REGISTRATION_NOT_FOUND);
                });
    registration.setStatus(RegistrationStatus.ATTENDED);
    registration.setCheckinTime(LocalDateTime.now());
    registration.updatedBy(userId);
    registrationRepository.save(registration);
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
                      "No active registration found for user {} and event {}", userId, eventId);
                  return new BusinessException(ErrorCode.REGISTRATION_NOT_FOUND);
                });
    registration.setActive(false);
    registration.setStatus(RegistrationStatus.CANCELED);
    registration.updatedBy(userId);
    registrationRepository.save(registration);
    log.info("User {} successfully cancelled registration to event {}", userId, eventId);
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
            .findByEventIdAndUserIdAndIsActiveTrue(
                eventId, updateRegistrationStatusRequest.getUserId())
            .orElseThrow(
                () -> {
                  log.warn(
                      "No active registration found for user {} and event {}",
                      updateRegistrationStatusRequest.getUserId(),
                      eventId);
                  return new BusinessException(ErrorCode.REGISTRATION_NOT_FOUND);
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
    List<EventRegistration> registrations =
        registrationRepository.findByUserIdAndIsActiveTrue(userId);
    return registrations.stream()
        .map(
            reg -> {
              Event event = reg.getEvent();
              return UserEventResponse.builder()
                  .eventId(event.getId())
                  .eventName(event.getName())
                  .startTime(event.getStartTime())
                  .endTime(event.getEndTime())
                  .registrationStatus(reg.getStatus())
                  .build();
            })
        .toList();
  }

  /**
   * Retrieves detailed information about a specific event the current user has registered for.
   *
   * @param eventId the ID of the event
   * @return UserEventDetailResponse containing detailed information about the user's event
   * @throws BusinessException if no active registration is found for the user and event
   */
  @Override
  public UserEventDetailResponse getUserEventDetail(Long eventId) {
    log.info("Fetching user event detail for user {}", eventId);
    Long userId = getCurrentUserId();
    EventRegistration registration =
        registrationRepository
            .findByEventIdAndUserIdAndIsActiveTrue(eventId, userId)
            .orElseThrow(
                () -> {
                  log.warn(
                      "No active registration found for user {} and event {}", userId, eventId);
                  return new BusinessException(ErrorCode.REGISTRATION_NOT_FOUND);
                });
    Event event = registration.getEvent();
    log.info("User {} successfully registered to event {}", userId, eventId);
    return UserEventDetailResponse.builder()
        .eventId(event.getId())
        .registrationId(registration.getId())
        .ticketCode(registration.getQrCode())
        .eventCode(event.getCode())
        .eventName(event.getName())
        .location(event.getLocationDetail())
        .startTime(event.getStartTime())
        .endTime(event.getEndTime())
        .checkInTime(registration.getCheckinTime())
        .registrationStatus(registration.getStatus())
        .registrationStatus(registration.getStatus())
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
      registrations =
          registrationRepository.findByEventIdAndStatusAndIsActiveTrue(eventId, status, pageable);
    } else {
      registrations = registrationRepository.findByEventIdAndIsActiveTrue(eventId, pageable);
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
              .build();
        });
  }

  private Long getCurrentUserId() {
    return Long.valueOf(
        SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
  }

  private String randomCode(LocalDateTime startTime) {
    LocalDateTime now = LocalDateTime.now();
    String datePart = startTime.format(DateTimeFormatter.ofPattern("ddMMyy"));
    String secondPart = String.format("%06d", now.getSecond());
    return "CS_" + datePart + "_" + secondPart;
  }
}
