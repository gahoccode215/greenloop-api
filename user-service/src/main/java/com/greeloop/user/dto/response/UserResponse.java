package com.greeloop.user.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class UserResponse {
    private Long userId;
    private String email;
    private String fullName;
    private String role;
    private Boolean isEmailVerified;
    private LocalDateTime createdAt;
}
