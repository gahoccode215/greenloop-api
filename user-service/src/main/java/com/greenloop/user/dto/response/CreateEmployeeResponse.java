package com.greenloop.user.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CreateEmployeeResponse {
  private Long id;
  private String email;
  private String fullName;
  private String role;
  private String department;
  private Boolean isActive;
  private String temporaryPassword; // Chỉ hiển thị 1 lần
  private String message;
}
