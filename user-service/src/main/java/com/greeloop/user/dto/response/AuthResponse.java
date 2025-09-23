package com.greeloop.user.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private String type;
    private Long userId;
    private String email;
    private String role;
    private long expiresIn;
    private long refreshExpiresIn;
}

