package com.greenloop.order.command;

import com.greenloop.order.enums.OrderStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.axonframework.modelling.command.TargetAggregateIdentifier;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UpdateOrderStatusCommand {

    @TargetAggregateIdentifier
    private String orderId;

    private OrderStatus newStatus;
    private String reason;

    private String goshipShipmentId;
    private String goshipTrackingCode;
    private String carrier;
}
