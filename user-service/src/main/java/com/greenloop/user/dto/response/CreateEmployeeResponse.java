package com.greenloop.user.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CreateEmployeeResponse {
    private Long id;
    private String email;
    private String fullName;
    private String phoneNumber;
    private String role;
    private String temporaryPassword;
    private Boolean isActive;
    private Boolean isEmailVerified;
}
