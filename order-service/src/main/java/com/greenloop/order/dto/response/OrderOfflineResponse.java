package com.greenloop.order.dto.response;

import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderOfflineResponse {
    private String orderId;
    private String orderCode;
    private Long eventId;

    private Long customerId;
    private String customerName;
    private String customerPhone;

    private Boolean isGuestPurchase;

    private List<OrderItemResponse> items;

    private BigDecimal subtotal;
    private BigDecimal discountAmount;
    private BigDecimal totalPrice;

    private String voucherCode;

    private String paymentMethod;
    private LocalDateTime createdAt;
    private String createdBy;
    private Integer earnedEcoPoints;
    private String paymentProofImageUrl;
}
