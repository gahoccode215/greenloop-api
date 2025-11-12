package com.greenloop.event.dto.request;

import com.greenloop.event.constraint.ValidEventTime;
import com.greenloop.event.enums.EventStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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
public class EventRequest {

  @NotBlank(message = "Event name is required")
  private String name;

  @NotBlank(message = "Event description is required")
  private String description;

  @NotNull(message = "Start time is required")
  private LocalDateTime startTime;

  @NotNull(message = "End time is required")
  private LocalDateTime endTime;

  @NotBlank(message = "Location is required")
  private String location;

  @NotNull(message = "Event status is required")
  private EventStatus status;

  @NotBlank(message = "Latitude is required")
  private String latitude;

  @NotBlank(message = "Longitude is required")
  private String longitude;

  @NotBlank(message = "Note is required")
  private String note;
}
