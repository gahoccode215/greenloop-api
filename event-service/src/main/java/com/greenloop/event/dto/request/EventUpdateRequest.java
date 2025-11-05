package com.greenloop.event.dto.request;

import com.greenloop.event.constraint.ValidEventTime;
import com.greenloop.event.enums.EventStatus;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@ValidEventTime
public class EventUpdateRequest {

  private String name;

  private String description;

  private LocalDateTime startTime;

  private LocalDateTime endTime;

  private String location;

  private EventStatus status;

  private String latitude;

  private String longitude;

  private String note;
}
