package com.greenloop.event.service.impl;

import com.greenloop.event.dto.response.EventRegistrationStatisticsResponse;
import com.greenloop.event.dto.response.EventStaffStatisticsResponse;
import com.greenloop.event.dto.response.EventStatisticsResponse;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.enums.RegistrationStatus;
import com.greenloop.event.repository.EventRegistrationRepository;
import com.greenloop.event.repository.EventRepository;
import com.greenloop.event.repository.EventStaffAssignmentRepository;
import com.greenloop.event.service.DashboardService;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class DashboardServiceImpl implements DashboardService {

  private final EventRepository eventRepository;
  private final EventRegistrationRepository eventRegistrationRepository;
  private final EventStaffAssignmentRepository eventStaffAssignmentRepository;

  @Override
  public EventStatisticsResponse getEventStatistics() {
    Long totalEvents = eventRepository.count();

    Map<EventStatus, Long> byStatus =
        Arrays.stream(EventStatus.values())
            .collect(
                Collectors.toMap(
                    status -> status, status -> eventRepository.countByStatus(status)));

    List<EventStatisticsResponse.MonthlyEventCount> monthlyCreated =
        eventRepository.countEventsByMonth().stream()
            .map(
                row ->
                    EventStatisticsResponse.MonthlyEventCount.builder()
                        .month((String) row[0])
                        .count((Long) row[1])
                        .build())
            .collect(Collectors.toList());

    List<EventStatisticsResponse.TopEventRegistration> topEvents =
        eventRepository.findTopEventsByRegistration().stream()
            .map(
                row ->
                    EventStatisticsResponse.TopEventRegistration.builder()
                        .eventId((Long) row[0])
                        .eventName((String) row[1])
                        .registrations((Long) row[2])
                        .build())
            .collect(Collectors.toList());

    return EventStatisticsResponse.builder()
        .totalEvents(totalEvents)
        .byStatus(byStatus)
        .monthlyCreated(monthlyCreated)
        .topEventsByRegistration(topEvents)
        .build();
  }

  @Override
  public EventRegistrationStatisticsResponse getEventRegistrationStatistics() {
    Long totalRegistrations = eventRegistrationRepository.count();

    Map<RegistrationStatus, Long> byStatus =
        Arrays.stream(RegistrationStatus.values())
            .collect(
                Collectors.toMap(
                    status -> status, status -> eventRegistrationRepository.countByStatus(status)));

    List<EventRegistrationStatisticsResponse.CheckinTrend> checkinTrend =
        eventRegistrationRepository.countCheckinByDate().stream()
            .map(
                row ->
                    EventRegistrationStatisticsResponse.CheckinTrend.builder()
                        .date((LocalDateTime) row[0])
                        .count((Long) row[1])
                        .build())
            .collect(Collectors.toList());

    List<EventRegistrationStatisticsResponse.TopUserRegistration> topUsers =
        eventRegistrationRepository.findTopUsers().stream()
            .map(
                row ->
                    EventRegistrationStatisticsResponse.TopUserRegistration.builder()
                        .userId((Long) row[0])
                        .registrations((Long) row[1])
                        .build())
            .collect(Collectors.toList());

    return EventRegistrationStatisticsResponse.builder()
        .totalRegistrations(totalRegistrations)
        .byStatus(byStatus)
        .checkinTrend(checkinTrend)
        .topUsers(topUsers)
        .build();
  }

  @Override
  public EventStaffStatisticsResponse getEventStaffStatistics() {
    Long totalAssignments = eventStaffAssignmentRepository.count();
    Long storeManagers = eventStaffAssignmentRepository.countByIsStoreManager(true);

    List<EventStaffStatisticsResponse.EventStaffCount> byEvent =
        eventStaffAssignmentRepository.countStaffByEvent().stream()
            .map(
                row ->
                    EventStaffStatisticsResponse.EventStaffCount.builder()
                        .eventId((Long) row[0])
                        .staffCount((Long) row[1])
                        .storeManagers((Long) row[2])
                        .build())
            .collect(Collectors.toList());

    return EventStaffStatisticsResponse.builder()
        .totalAssignments(totalAssignments)
        .storeManagers(storeManagers)
        .byEvent(byEvent)
        .build();
  }
}
