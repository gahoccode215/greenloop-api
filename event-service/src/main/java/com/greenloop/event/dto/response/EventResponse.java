package com.greenloop.event.dto.response;

import com.greenloop.event.enums.EventStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
public class EventResponse {
    private Long id;
    private String code;
    private String name;
    private String location;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private EventStatus status;
    private String latitude;
    private String longitude;
    private Boolean isRegistered;
}
