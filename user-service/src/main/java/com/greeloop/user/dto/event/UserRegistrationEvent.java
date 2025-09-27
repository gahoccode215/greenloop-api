package com.greeloop.user.dto.event;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class UserRegistrationEvent {
    private String email;
    private String otpCode;
    private LocalDateTime otpExpiryTime;
}
