package com.greenloop.event.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class RegisterEventRequest {
  @Schema(
      description = "Optional note for the event registration",
      example = "Looking forward to the event!")
  private String note;
}
