package com.greenloop.order.command;

import com.greenloop.order.dto.request.CheckoutShippingAddressRequest;
import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import lombok.Builder;
import lombok.Data;
import org.axonframework.modelling.command.TargetAggregateIdentifier;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class CreateOrderCommand {

    @TargetAggregateIdentifier
    private final String orderId;

    private final String orderCode;
    private final Long customerId;
    private final PaymentStatus paymentStatus;
    private final OrderStatus orderStatus;
    private final BigDecimal totalPrice;
    private final BigDecimal shippingFee;
    private final List<OrderItemRequest> orderItems;
    private final CheckoutShippingAddressRequest shippingAddress;
    private final PaymentMethod paymentMethod;
    private final Long paymentOrderCode;

    private final String selectedRateId;
    private final String carrier;
    private final LocalDateTime expectedDeliveryTime;
}
