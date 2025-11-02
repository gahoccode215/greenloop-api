package com.greenloop.event.dto.response;

import com.greenloop.event.enums.RegistrationStatus;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EventUserRegistrationResponse {
  private Long userId;
  private String email;
  private String fullName;
  private Boolean isActive;
  private LocalDateTime createdAt;
  private LocalDateTime checkInTime;
  private RegistrationStatus registrationStatus;
}
