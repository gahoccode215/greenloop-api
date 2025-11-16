package com.greenloop.order.command;

import lombok.Builder;
import lombok.Data;
import org.axonframework.modelling.command.TargetAggregateIdentifier;

@Data
@Builder
public class UpdateShippingStatusCommand {
    @TargetAggregateIdentifier
    private final String orderId;
    private final String shippingStatus;
}
