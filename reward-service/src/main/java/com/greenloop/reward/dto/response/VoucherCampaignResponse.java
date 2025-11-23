package com.greenloop.reward.dto.response;

import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class VoucherCampaignResponse {
<<<<<<< HEAD
  private Long campaignId;
  private String campaignName;
  private String campaignDescription;
  private LocalDateTime startDate;
  private LocalDateTime endDate;
  private Boolean isActive;
=======
    private Long campaignId;
    private String campaignName;
    private String campaignDescription;
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Long updateBy;
    private Boolean isActive;
>>>>>>> 72d9b53043cee7b8784c1d48740c6fc6821d00ca
}
