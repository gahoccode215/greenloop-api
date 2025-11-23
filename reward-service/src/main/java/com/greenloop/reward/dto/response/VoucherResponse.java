package com.greenloop.reward.dto.response;

import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherType;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class VoucherResponse {
    private Long voucherId;
    private Long campaignId;
    private String code;
    private String name;
    private String description;
    private VoucherStatus voucherStatus;
    private VoucherType voucherType;
    private BigDecimal value;
    private BigDecimal minOrderValue;
    private BigDecimal maxDiscount;
    private LocalDateTime expiryDate;
    private Integer quantity;
    private Integer availableQuantity;
    private Integer pointToRedeem;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Long updateBy;
    private Boolean active;
}