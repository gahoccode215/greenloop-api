package com.greenloop.order.dto.response;

import lombok.*;
import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CheckoutResponse {
    private String orderId;
    private String orderCode;
    private String paymentUrl;
    private String message;
    private LocalDateTime createdAt;
}
