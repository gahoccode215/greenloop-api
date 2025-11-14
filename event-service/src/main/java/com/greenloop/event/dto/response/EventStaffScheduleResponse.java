package com.greenloop.event.dto.response;

import com.greenloop.event.enums.EventStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Builder
public class EventStaffScheduleResponse {
    private Long staffId;
    private String fullName;
    private String email;
    private Boolean isStoreManager;
    private Long eventId;
    private String code;
    private String name;
    private String location;
    private String imageUrl;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private EventStatus status;
    private String latitude;
    private String longitude;

}
