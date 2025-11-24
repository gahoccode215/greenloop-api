package com.greenloop.order.command.event;

import com.greenloop.order.dto.request.CheckoutShippingAddressRequest;
import com.greenloop.order.dto.request.OrderItemRequest;
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
@AllArgsConstructor
@NoArgsConstructor
public class OrderCreatedEvent {

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

    private String parcelWeight;
    private String parcelWidth;
    private String parcelHeight;
    private String parcelLength;

    private Integer shippingStatus;

}
