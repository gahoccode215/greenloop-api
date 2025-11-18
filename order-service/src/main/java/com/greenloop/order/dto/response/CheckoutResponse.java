package com.greenloop.order.dto.response;

import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Response DTO cho checkout API
 * Trả về thông tin đơn hàng đã tạo bao gồm chi tiết phí vận chuyển
 */
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
