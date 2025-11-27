package com.greenloop.order.command.event;

import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class POSOrderCreatedEvent {

    private String orderId;
    private String orderCode;
    private OrderType orderType;

    // Customer
    private Long customerId;
    private Boolean isGuestPurchase;

    // Event
    private Long eventLocationId;
    private Long posStaffId;

    // Order details
    private BigDecimal totalPrice;
    private OrderStatus orderStatus;
    private PaymentStatus paymentStatus;
    private PaymentMethod paymentMethod;
    private Long paymentOrderCode;

    private List<OrderItemRequest> orderItems;
}
