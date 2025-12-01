package com.greenloop.event.worker;

import com.greenloop.event.entity.Event;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.repository.EventRepository;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
public class EventStatusScheduler {

  private final EventRepository eventRepository;

  @Scheduled(cron = "0 0 * * * *")
  @Transactional
  public void updateEventStatuses() {
    log.info("Starting scheduled event status update");

    LocalDateTime now = LocalDateTime.now();
    LocalDateTime twoDaysFromNow = now.plusDays(2);

    try {
      int closedCount = updateClosedEvents(now);
      int ongoingCount = updateOngoingEvents(now);
      int upcomingCount = updateUpcomingEvents(now, twoDaysFromNow);
      log.info(
          "Event status update completed - Closed: {}, Ongoing: {}, Upcoming: {}",
          closedCount,
          ongoingCount,
          upcomingCount);
    } catch (Exception e) {
      log.error("Error occurred during event status update: {}", e.getMessage(), e);
    }
  }

  private int updateClosedEvents(LocalDateTime now) {
    List<Event> eventsToClose =
        eventRepository.findByStatusAndIsActiveAndEndTimeBefore(EventStatus.PUBLISHED, true, now);

    eventsToClose.addAll(
        eventRepository.findByStatusAndIsActiveAndEndTimeBefore(EventStatus.ONGOING, true, now));

    eventsToClose.addAll(
        eventRepository.findByStatusAndIsActiveAndEndTimeBefore(EventStatus.UPCOMING, true, now));

    eventsToClose.forEach(
        event -> {
          event.setStatus(EventStatus.CLOSED);
          event.setActive(false);
          log.debug("Event {} status changed to CLOSED", event.getCode());
        });

    return eventsToClose.size();
  }

  private int updateOngoingEvents(LocalDateTime now) {
    List<Event> eventsToStart =
        eventRepository.findByStatusAndIsActiveAndStartTimeBeforeAndEndTimeAfter(
            EventStatus.PUBLISHED, true, now, now);

    eventsToStart.addAll(
        eventRepository.findByStatusAndIsActiveAndStartTimeBeforeAndEndTimeAfter(
            EventStatus.UPCOMING, true, now, now));

    eventsToStart.forEach(
        event -> {
          event.setStatus(EventStatus.ONGOING);
          log.debug("Event {} status changed to ONGOING", event.getCode());
        });

    return eventsToStart.size();
  }

  private int updateUpcomingEvents(LocalDateTime now, LocalDateTime twoDaysFromNow) {
    List<Event> eventsUpcoming =
        eventRepository.findByStatusAndIsActiveAndStartTimeBetween(
            EventStatus.PUBLISHED, true, now, twoDaysFromNow);

    eventsUpcoming.forEach(
        event -> {
          event.setStatus(EventStatus.UPCOMING);
          log.debug("Event {} status changed to UPCOMING", event.getCode());
        });

    return eventsUpcoming.size();
  }
}
