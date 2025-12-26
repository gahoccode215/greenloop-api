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
    private BigDecimal discountAmount;
    private String voucherCode;
    private BigDecimal originalShippingFee;
    private BigDecimal productDiscount;
    private BigDecimal shippingDiscount;
    private Boolean isFreeShip;
    private BigDecimal subtotalAfterDiscount;
}
