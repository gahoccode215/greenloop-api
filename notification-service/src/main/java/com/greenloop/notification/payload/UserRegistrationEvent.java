package com.greenloop.notification.payload;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRegistrationEvent {
  private String email;
  private String otpCode;
  private LocalDateTime otpExpiryTime;
}
