package com.greenloop.order.dto.response;

import lombok.*;
import java.math.BigDecimal;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentResponse {
    private String paymentUrl;
    private String orderId;
    private String orderCode;
    private BigDecimal amount;
}
