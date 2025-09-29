package com.greeloop.user.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserProfileResponse {
    private Long userId;
    private String email;
    private String firstName;
    private String lastName;
    private String role;
    private Boolean isActive;
}