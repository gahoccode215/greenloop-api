package com.greenloop.order.command;

import com.greenloop.order.enums.OrderStatus;
import lombok.Builder;
import lombok.Data;
import org.axonframework.modelling.command.TargetAggregateIdentifier;

@Data
@Builder
public class SystemUpdateOrderStatusCommand {
    @TargetAggregateIdentifier
    private final String orderId;
    private final OrderStatus orderStatus;
    private final String source;  // "GHN_WEBHOOK", "ADMIN_FORCE"...
}
