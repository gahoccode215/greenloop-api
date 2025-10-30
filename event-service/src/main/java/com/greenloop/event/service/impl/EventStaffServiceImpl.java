package com.greenloop.event.service.impl;

import com.greenloop.event.constraint.RoleConstants;
import com.greenloop.event.dto.request.AssignStaffListRequest;
import com.greenloop.event.dto.response.EventStaffResponse;
import com.greenloop.event.dto.response.UserProfileResponse;
import com.greenloop.event.entity.Event;
import com.greenloop.event.entity.EventStaffAssignment;
import com.greenloop.event.enums.ErrorCode;
import com.greenloop.event.exception.BusinessException;
import com.greenloop.event.repository.EventRepository;
import com.greenloop.event.repository.EventStaffAssignmentRepository;
import com.greenloop.event.service.EventStaffService;
import com.greenloop.event.service.UserServiceFeign;
import jakarta.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EventStaffServiceImpl implements EventStaffService {

  private final EventRepository eventRepository;
  private final EventStaffAssignmentRepository assignmentRepository;
  private final UserServiceFeign userServiceFeign;

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
            .orElseThrow(() -> new BusinessException(ErrorCode.EVENT_NOT_FOUND));

    boolean hasStoreManager =
        assignmentRepository.existsByEventIdAndIsStoreManagerTrue(event.getId());
    List<EventStaffAssignment> assignments = new ArrayList<>();

    for (AssignStaffListRequest.StaffAssignmentDTO dto : request.getStaffAssignments()) {
      UserProfileResponse user = userServiceFeign.getUserInfoById(dto.getStaffId());
      if (user == null || Boolean.FALSE.equals(user.getIsActive())) {
        throw new BusinessException(ErrorCode.USER_NOT_FOUND);
      }

      if (assignmentRepository.existsByEventIdAndStaffId(event.getId(), dto.getStaffId())) {
        throw new BusinessException(ErrorCode.STAFF_ALREADY_ASSIGNED);
      }

      if (dto.isStoreManager()) {
        if (!user.getRoles().contains(RoleConstants.STORE_MANAGER)) {
          throw new BusinessException(ErrorCode.INVALID_ROLE);
        }
        if (hasStoreManager) {
          throw new BusinessException(ErrorCode.STORE_MANAGER_ALREADY_ASSIGNED);
        }
        hasStoreManager = true;
      } else {
        if (!user.getRoles().contains(RoleConstants.STAFF)) {
          throw new BusinessException(ErrorCode.INVALID_ROLE);
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
  public void updateStaffAssignments(Long eventId, AssignStaffListRequest request) {
    Long currentUserId =
        Long.valueOf(
            SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    log.info("User {} is updating staff assignments for event {}", currentUserId, eventId);
    Event event =
        eventRepository
            .findById(eventId)
            .orElseThrow(() -> new BusinessException(ErrorCode.EVENT_NOT_FOUND));

    List<EventStaffAssignment> currentAssignments =
        assignmentRepository.findByEventIdAndIsActiveTrue(eventId);

    Map<Long, Boolean> newAssignments =
        request.getStaffAssignments().stream()
            .collect(
                Collectors.toMap(
                    AssignStaffListRequest.StaffAssignmentDTO::getStaffId,
                    AssignStaffListRequest.StaffAssignmentDTO::isStoreManager));

    currentAssignments.stream()
        .filter(a -> !newAssignments.containsKey(a.getStaffId()))
        .forEach(
            a -> {
              a.setActive(false);
              a.updatedBy(currentUserId);
            });

    Set<Long> currentStaffIds =
        currentAssignments.stream()
            .map(EventStaffAssignment::getStaffId)
            .collect(Collectors.toSet());

    List<EventStaffAssignment> toAdd =
        newAssignments.entrySet().stream()
            .filter(e -> !currentStaffIds.contains(e.getKey()))
            .map(
                e ->
                    EventStaffAssignment.builder()
                        .event(event)
                        .staffId(e.getKey())
                        .isStoreManager(e.getValue())
                        .build())
            .toList();
    assignmentRepository.saveAll(toAdd);

    currentAssignments.stream()
        .filter(a -> newAssignments.containsKey(a.getStaffId()))
        .filter(a -> a.isStoreManager() != newAssignments.get(a.getStaffId()))
        .forEach(
            a -> {
              a.setStoreManager(newAssignments.get(a.getStaffId()));
              a.updatedBy(currentUserId);
            });

    assignmentRepository.saveAll(currentAssignments);

    long storeManagerCount =
        assignmentRepository.findByEventIdAndIsActiveTrue(eventId).stream()
            .filter(EventStaffAssignment::isStoreManager)
            .count();
    if (storeManagerCount > 1) {
      throw new BusinessException(ErrorCode.STORE_MANAGER_ALREADY_ASSIGNED);
    }
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
}
