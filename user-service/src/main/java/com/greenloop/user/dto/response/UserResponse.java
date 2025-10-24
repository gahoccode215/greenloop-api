package com.greenloop.user.dto.response;

import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserResponse {
  private Long userId;
  private String email;
  private String firstName;
  private String lastName;
  private String phoneNumber;
  private String role;
  private Boolean isActive;
  private Boolean isEmailVerified;
  private LocalDateTime createdAt;
}
