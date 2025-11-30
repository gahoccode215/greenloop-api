package com.greenloop.reward.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RedeemVoucherRequest {

    private Long voucherUserId;
    private Long orderId;
    private BigDecimal discountValue;
}
