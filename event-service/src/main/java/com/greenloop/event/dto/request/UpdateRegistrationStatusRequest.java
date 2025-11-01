package com.greenloop.event.dto.request;

import com.greenloop.event.enums.RegistrationStatus;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UpdateRegistrationStatusRequest {
  @NotNull(message = "User ID must not be null")
  private Long userId;

  @NotNull(message = "Registration status must not be null")
  private RegistrationStatus registrationStatus;
}
