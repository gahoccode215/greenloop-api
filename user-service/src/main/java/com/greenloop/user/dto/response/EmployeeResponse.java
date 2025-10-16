package com.greenloop.user.dto.response;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Builder
public class EmployeeResponse {
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String department;
    private Boolean isActive;
    private String avatarUrl;
    private LocalDateTime createdAt;
}
