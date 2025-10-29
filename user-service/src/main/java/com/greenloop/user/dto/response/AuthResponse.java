package com.greenloop.user.dto.response;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
// @JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {
  private String accessToken;
  private String refreshToken;
  private String type;
  private Long userId;
  private String email;
  private List<String> roles;
  private long expiresIn;
  private long refreshExpiresIn;
}
