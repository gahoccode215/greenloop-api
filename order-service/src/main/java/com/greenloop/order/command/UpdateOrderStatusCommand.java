package com.greenloop.order.command;

import com.greenloop.order.enums.OrderStatus;
import lombok.Builder;
import lombok.Data;
import org.axonframework.modelling.command.TargetAggregateIdentifier;

@Data
@Builder
public class UpdateOrderStatusCommand {
    @TargetAggregateIdentifier
    private String orderId;
    private OrderStatus orderStatus;
}
