package com.greenloop.reward.dto.request;

import jakarta.validation.constraints.FutureOrPresent;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.List;
import lombok.Data;

@Data
public class CreateVoucherCampaignRequest {

  @NotBlank(message = "Campaign name is required")
  private String campaignName;

  private String description;

  @NotNull(message = "Start date is required")
<<<<<<< HEAD
  @FutureOrPresent(message = "Start date must be today or in the future")
  private LocalDateTime startDate;

  @NotNull(message = "End date is required")
=======
  private LocalDateTime startDate;

  @NotNull(message = "End date is required")
  @FutureOrPresent(message = "End date must be in the future")
>>>>>>> 72d9b53043cee7b8784c1d48740c6fc6821d00ca
  private LocalDateTime endDate;

  private List<CreateVoucherRequest> vouchers;
}
