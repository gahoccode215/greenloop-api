package com.greenloop.event.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import lombok.Data;

@Data
public class AssignStaffListRequest {

  @NotNull(message = "Event ID must not be null")
  private Long eventId;

  @NotEmpty(message = "Staff assignment list must not be empty")
  @Valid
  private List<StaffAssignmentDTO> staffAssignments;

  @Data
  public static class StaffAssignmentDTO {

    @NotNull(message = "Staff ID must not be null")
    private Long staffId;

    private boolean isStoreManager;
  }
}
