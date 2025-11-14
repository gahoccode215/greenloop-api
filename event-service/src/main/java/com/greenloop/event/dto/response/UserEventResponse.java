package com.greenloop.event.dto.response;

import com.greenloop.event.enums.RegistrationStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class UserEventResponse {
    private Long registerId;
    private Long eventId;
    private String eventCode;
    private String eventName;
    private String imageUrl;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private RegistrationStatus registrationStatus;
}
