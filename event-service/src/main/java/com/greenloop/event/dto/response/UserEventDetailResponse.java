package com.greenloop.event.dto.response;

import com.greenloop.event.enums.RegistrationStatus;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserEventDetailResponse {
  private Long eventId;
  private Long registrationId;
  private String ticketCode;
  private String imageUrl;
  private String eventCode;
  private String eventName;
  private String location;
  private LocalDateTime startTime;
  private LocalDateTime endTime;
  private String latitude;
  private String longitude;
  private LocalDateTime checkInTime;
  private RegistrationStatus registrationStatus;
  private boolean isActive;
}
