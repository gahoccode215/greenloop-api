package com.greenloop.order.command;

import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.enums.OrderStatus;
import lombok.Builder;
import lombok.Data;
import org.axonframework.modelling.command.TargetAggregateIdentifier;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
public class CreateOrderCommand {
    @TargetAggregateIdentifier
    private final String orderId;
    private final String orderCode;
    private final Long customerId;
    private final OrderStatus orderStatus;
    private final BigDecimal totalPrice;
    private final List<OrderItemRequest> orderItems;
}
