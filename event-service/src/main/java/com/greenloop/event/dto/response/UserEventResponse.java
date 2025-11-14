package com.greenloop.event.dto.response;

import com.greenloop.event.enums.RegistrationStatus;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserEventResponse {
  private Long registerId;
  private Long eventId;
  private String eventCode;
  private String eventName;
  private String imageUrl;
  private LocalDateTime startTime;
  private LocalDateTime endTime;
  private RegistrationStatus registrationStatus;
}
