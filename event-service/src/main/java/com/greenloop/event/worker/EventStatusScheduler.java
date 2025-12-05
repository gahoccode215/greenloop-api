package com.greenloop.event.worker;

import com.greenloop.event.dto.event.NotificationEvent;
import com.greenloop.event.entity.Event;
import com.greenloop.event.entity.EventRegistration;
import com.greenloop.event.entity.EventStaffAssignment;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.repository.EventRepository;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import com.greenloop.event.service.NotificationProducer;
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
  private final NotificationProducer notificationProducer;

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

    private void sendNotifications(Event event, EventStatus status) {

        List<Long> userIds = new ArrayList<>();
        userIds.addAll(event.getStaffAssignments().stream()
                .map(EventStaffAssignment::getStaffId).toList());
        userIds.addAll(event.getRegistrations().stream()
                .map(EventRegistration::getUserId).toList());

        for (Long userId : userIds) {

            NotificationEvent.NotificationEventBuilder builder = NotificationEvent.builder()
                    .userId(userId);

            switch (status) {

                case CLOSED -> {
                    builder.title("Sự kiện đã kết thúc")
                            .message("Sự kiện " + event.getName() + " đã chính thức kết thúc. Cảm ơn bạn đã tham gia!");
                }

                case CANCELED -> {
                    builder.title("Sự kiện đã bị hủy")
                            .message("Sự kiện " + event.getName() + " đã bị hủy bỏ. Chúng tôi xin lỗi vì sự bất tiện này.");
                }

                case UPCOMING -> {
                    builder.title("Sự kiện sắp diễn ra")
                            .message("Sự kiện " + event.getName() +
                                    " sẽ diễn ra vào " +
                                    event.getStartTime().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")) +
                                    ". Hãy chuẩn bị tham gia nhé!");
                }
            }

            notificationProducer.sendNotificationMessage(builder.build());
        }
    }
}
