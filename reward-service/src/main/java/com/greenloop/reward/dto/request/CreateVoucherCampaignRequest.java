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
  private LocalDateTime startDate;

  @NotNull(message = "End date is required")
  @FutureOrPresent(message = "End date must be in the future")
  private LocalDateTime endDate;

  private List<CreateVoucherRequest> vouchers;
}
