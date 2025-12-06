package com.greenloop.order.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VoucherDiscountResult {

    private Long voucherUserId;
    private String voucherCode;
    private String voucherName;
    private BigDecimal discountAmount;
    private BigDecimal finalAmount;

    private BigDecimal shippingDiscount;
    private Boolean isFreeShip;
    private String discountType;

    public static VoucherDiscountResult noDiscount() {
        return VoucherDiscountResult.builder()
                .voucherUserId(null)
                .voucherCode(null)
                .voucherName(null)
                .discountAmount(BigDecimal.ZERO)
                .finalAmount(BigDecimal.ZERO)
                .shippingDiscount(BigDecimal.ZERO)
                .isFreeShip(false)
                .discountType(null)
                .build();
    }
}
