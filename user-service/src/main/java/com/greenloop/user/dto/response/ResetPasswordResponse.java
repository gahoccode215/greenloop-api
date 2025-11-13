package com.greenloop.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ResetPasswordResponse {
  private Long id;
  private String email;
  private String fullName;
  private String temporaryPassword;
  private String message;
}
