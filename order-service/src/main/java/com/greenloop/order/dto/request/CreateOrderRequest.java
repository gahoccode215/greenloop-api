package com.greenloop.order.dto.request;

import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateOrderRequest {
    private String orderId;
    private String orderCode;
    private Long customerId;
    private BigDecimal totalPrice;
    private BigDecimal shippingFee;
    private OrderStatus orderStatus;
    private PaymentStatus paymentStatus;
    private PaymentMethod paymentMethod;
    private Long paymentOrderCode;

    private List<OrderItemRequest> orderItems;
    private CheckoutShippingAddressRequest shippingAddress;

    private String selectedRateId;
    private String carrier;
    private LocalDateTime expectedDeliveryTime;
    private Integer shippingStatus;

    private String parcelWeight;
    private String parcelWidth;
    private String parcelHeight;
    private String parcelLength;

    private BigDecimal subTotal;
    private BigDecimal discountAmount;
    private Long voucherUserId;
    private String voucherCode;

}
