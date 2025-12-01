package com.greenloop.order.dto.response;

import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;


@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CheckoutResponse {
    private String orderId;
    private String orderCode;
    private BigDecimal productTotal;
    private BigDecimal shippingFee;
    private BigDecimal totalPrice;
    private String selectedCarrier;
    private String estimatedDelivery;
    private String paymentUrl;
    private String message;
    private LocalDateTime createdAt;
}
