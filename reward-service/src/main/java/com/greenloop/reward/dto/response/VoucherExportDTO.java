package com.greenloop.reward.dto.response;


import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class VoucherExportDTO {
    private String campaignId;
    private String campaignName;
    private String campaignDescription;
    private String campaignStartDate;
    private String campaignEndDate;

    private String voucherId;
    private String voucherCode;
    private String voucherName;
    private String voucherDescription;
    private String type;
    private String value;
    private String minOrderValue;
    private String maxDiscount;
    private String status;
    private String expiryDate;
    private String quantity;
    private String usedQuantity;
    private String availableQuantity;
    private String pointToRedeem;
    private String createdAt;
    private String updatedAt;
}
