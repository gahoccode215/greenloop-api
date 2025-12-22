package com.greenloop.reward.dto.response;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class VoucherCampaignExportDTO {
    private String campaignId;
    private String campaignName;
    private String campaignDescription;
    private String startDate;
    private String endDate;
    private String totalVouchers;
    private String activeVouchers;
    private String expiredVouchers;
    private String totalQuantity;
    private String usedQuantity;
    private String availableQuantity;
    private String createdAt;
    private String updatedAt;
}