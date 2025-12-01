package com.greenloop.event.dto.response;

import com.greenloop.event.enums.EventStatus;
import java.util.List;
import java.util.Map;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EventStatisticsResponse {
  private Long totalEvents;
  private Map<EventStatus, Long> byStatus;
  private List<MonthlyEventCount> monthlyCreated;
  private List<TopEventRegistration> topEventsByRegistration;

  @Data
  @Builder
  public static class MonthlyEventCount {
    private String month;
    private Long count;
  }

  @Data
  @Builder
  public static class TopEventRegistration {
    private Long eventId;
    private String eventName;
    private Long registrations;
  }
}
