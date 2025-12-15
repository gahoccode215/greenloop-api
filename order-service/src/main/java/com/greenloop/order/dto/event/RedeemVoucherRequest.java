package com.greenloop.order.dto.event;

import lombok.*;

import java.math.BigDecimal;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RedeemVoucherRequest {

    /**
     * ID của VoucherUser (voucher mà user đã đổi)
     */
    private Long voucherUserId;

    /**
     * ID của Order đã tạo
     */
    private String orderId;

    /**
     * Số tiền đã giảm thực tế
     */
    private BigDecimal discountValue;
}
