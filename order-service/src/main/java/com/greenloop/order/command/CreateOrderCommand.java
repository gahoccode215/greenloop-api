package com.greenloop.order.command;

import lombok.Builder;
import lombok.Data;
import org.axonframework.modelling.command.TargetAggregateIdentifier;

import java.math.BigDecimal;

@Data
@Builder
public class CreateOrderCommand {
    @TargetAggregateIdentifier
    private final String orderId;
    private final String orderCode;
    private final String customerId;
    private final String orderStatus;
    private final BigDecimal totalPrice;
}
