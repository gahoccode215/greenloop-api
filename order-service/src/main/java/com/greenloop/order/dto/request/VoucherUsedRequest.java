package com.greenloop.order.dto.request;

import lombok.Builder;
import lombok.Data;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class VoucherUsedRequest {
    private String orderId;
    private String orderCode;
    private Long customerId;
    private Long voucherUserId;
    private String voucherCode;
    private BigDecimal discountValue;
    private LocalDateTime usedAt;
}
