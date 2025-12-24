package com.greenloop.order.dto.redis;

import com.greenloop.order.dto.request.CheckoutShippingAddressRequest;
import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PendingOrderRedis implements Serializable {

    private static final long serialVersionUID = 1L;

    private String orderId;
    private String orderCode;
    private Long customerId;
    private Long eventId;
    private OrderType orderType;

    private PaymentMethod paymentMethod;
    private Long paymentOrderCode;
    private String paymentUrl;

    private BigDecimal subTotal;
    private BigDecimal discountAmount;
    private BigDecimal totalPrice;
    private BigDecimal shippingFee;

    private Long voucherUserId;
    private String voucherCode;

    private List<OrderItemRequest> items;

    private CheckoutShippingAddressRequest shippingAddress;
    private String selectedRateId;
    private String carrier;
    private LocalDateTime expectedDeliveryTime;
    private String parcelWeight;
    private String parcelWidth;
    private String parcelHeight;
    private String parcelLength;
    private Integer shippingStatus;

    private Boolean isGuestPurchase;
    private String guestName;
    private String guestPhone;

    private Integer earnedEcoPoints;
    private String note;
    private LocalDateTime createdAt;
    private String createdBy;
}
