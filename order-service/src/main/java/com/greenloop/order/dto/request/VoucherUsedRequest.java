package com.greenloop.order.dto.request;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VoucherUsedRequest {
    private String orderId;
    private String orderCode;
    private Long customerId;
    private Long voucherUserId;
    private String voucherCode;
    private BigDecimal discountValue;
    private LocalDateTime usedAt;
}
