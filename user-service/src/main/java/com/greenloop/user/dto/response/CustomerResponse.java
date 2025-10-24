package com.greenloop.user.dto.response;

import java.time.LocalDate;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomerResponse {
  private Long id;
  private String email;
  private String firstName;
  private String lastName;
  private String phoneNumber;
  private String avatarUrl;
  private LocalDate dateOfBirth;
  private String department;
  private Boolean isActive;
  private Boolean isEmailVerified;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
