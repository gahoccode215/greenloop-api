package com.greenloop.product.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class UserProfileResponse {
    private Long userId;
    private String email;
    private String fullName;
    private List<String> roles;
    private Boolean isActive;
}
