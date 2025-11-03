package com.greenloop.user.dto.response;

import com.greenloop.user.enums.Gender;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EmployeeResponse implements Serializable {
  private Long id;
  private String email;
  private String fullName;
  private String phoneNumber;
  private LocalDate dateOfBirth;
  private Gender gender;
  private String avatarUrl;
  private Boolean isActive;
  private List<String> roles;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
