package com.greenloop.user.dto.response;

import com.greenloop.user.enums.Gender;

import java.io.Serializable;
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
public class CustomerResponse implements Serializable {
  private Long id;
  private String email;
  private String fullName;
  private String phoneNumber;
  private String avatarUrl;
  private LocalDate dateOfBirth;
  private Gender gender;
  private String department;
  private Boolean isActive;
  private Boolean isEmailVerified;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
