package com.greenloop.event.dto.response;

import com.greenloop.event.enums.RegistrationStatus;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EventRegistrationStatisticsResponse {
  private Long totalRegistrations;
  private Map<RegistrationStatus, Long> byStatus;
  private List<CheckinTrend> checkinTrend;
  private List<TopUserRegistration> topUsers;

  @Data
  @Builder
  public static class CheckinTrend {
    private LocalDateTime date;
    private Long count;
  }

  @Data
  @Builder
  public static class TopUserRegistration {
    private Long userId;
    private Long registrations;
  }
}
