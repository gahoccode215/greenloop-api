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

    /**
     * Tạo result không có discount
     */
    public static VoucherDiscountResult noDiscount() {
        return VoucherDiscountResult.builder()
                .voucherUserId(null)
                .voucherCode(null)
                .voucherName(null)
                .discountAmount(BigDecimal.ZERO)
                .finalAmount(BigDecimal.ZERO)
                .build();
    }

    /**
     * Check xem có discount hay không
     */
    public boolean hasDiscount() {
        return voucherUserId != null
                && discountAmount != null
                && discountAmount.compareTo(BigDecimal.ZERO) > 0;
    }
}
