package com.greenloop.order.dto.event;

import lombok.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VoucherUsedEvent {
    private String orderId;
    private String orderCode;
    private Long customerId;
    private Long voucherUserId;
    private String voucherCode;
    private BigDecimal discountValue;
    private LocalDateTime usedAt;
}
