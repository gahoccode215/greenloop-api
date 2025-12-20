package com.greenloop.event.dto.response;

import com.greenloop.event.enums.RegistrationStatus;
import lombok.*;

import java.time.LocalDateTime;
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class EventExportDTO {
    private String eventId;
    private String eventCode;
    private String eventName;
    private String status;
    private String startTime;
    private String endTime;

    private String participantsCount;
    private String staffCount;
    private String checkinCount;

    private String userId;
    private String qrCode;
    private String checkinTime;
    private String registrationNote;
    private String registrationStatus;

    private String staffId;
    private String staffName;
    private String isStoreManager;
}