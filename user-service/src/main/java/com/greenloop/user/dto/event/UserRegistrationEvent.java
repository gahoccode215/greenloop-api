package com.greenloop.user.dto.event;

import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserRegistrationEvent {
  private String email;
  private String otpCode;
  private LocalDateTime otpExpiryTime;
}
