package com.greenloop.order.dto.response;

import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderResponse {
    private String orderId;
    private String orderCode;
    private Long customerId;
    private BigDecimal totalPrice;
    private BigDecimal shippingFee;
    private OrderStatus orderStatus;
    private PaymentStatus paymentStatus;
    private PaymentMethod paymentMethod;
    private Long paymentOrderCode;
    private String paymentTransactionId;

    private Integer shippingStatus;
    private String shippingStatusText;
    private String carrier;
    private LocalDateTime expectedDeliveryTime;
    private String goshipShipmentId;
    private String goshipTrackingUrl;
    private ShippingAddressResponse shippingAddress;

    private List<OrderItemResponse> orderItems;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    private OrderType orderType;
    private Long eventId;
    private String eventName;
    private Boolean isGuestPurchase;
    private String guestName;
    private String guestPhone;
    private String paymentProofImageUrl;
    private String createdBy;
    private BigDecimal subTotal;
    private BigDecimal discountAmount;
    private String voucherCode;
    private Integer earnedEcoPoints;
    private String note;
    private UserProfileResponse customerInfo;
}
