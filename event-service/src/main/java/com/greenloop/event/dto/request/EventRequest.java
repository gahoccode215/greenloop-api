package com.greenloop.event.dto.request;

import com.greenloop.event.constraint.ValidEventTime;
import com.greenloop.event.enums.EventStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.LocalDateTime;
import java.util.HashMap;
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

  @NotNull(message = "Google Place ID is required")
  @Size(min = 1, message = "Google Place ID cannot be empty")
  private HashMap<String, String> googlePlaceId;

  @NotBlank(message = "Latitude is required")
  private String latitude;

  @NotBlank(message = "Longitude is required")
  private String longitude;

  @NotBlank(message = "Note is required")
  private String note;
}
