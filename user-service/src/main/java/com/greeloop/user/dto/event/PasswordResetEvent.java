package com.greeloop.user.dto.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PasswordResetEvent {
    private String email;
    private String otpCode;
    private LocalDateTime otpExpiryTime;
}
