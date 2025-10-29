package com.greenloop.user.dto.response;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserProfileResponse {
  private Long userId;
  private String email;
  private String fullName;
  private List<String> roles;
  private Boolean isActive;
}
