package com.greenloop.notification.payload;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRegistrationEvent {
    private String email;
    private String otpCode;
    private LocalDateTime otpExpiryTime;
}
