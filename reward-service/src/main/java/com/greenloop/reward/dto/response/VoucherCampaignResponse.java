package com.greenloop.reward.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class VoucherCampaignResponse {
    private Long campaignId;
    private String campaignName;
    private String campaignDescription;
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private Boolean isActive;
}
