package com.greenloop.event.dto.response;

import com.greenloop.event.enums.UserRole;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Builder
public class UserInfoResponse {
  private Long id;
  private String fullName;
  private String email;
  private String phoneNumber;
  private List<UserRole> roles;
  private boolean isActive;
}
