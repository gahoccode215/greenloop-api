package com.greenloop.order.command;

import lombok.Builder;
import lombok.Data;
import org.axonframework.modelling.command.TargetAggregateIdentifier;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class UpdateShippingInfoCommand {
    @TargetAggregateIdentifier
    private final String orderId;
    private final String goshipShipmentId;
    private final String goshipTrackingCode;
    private final String carrier;
    private final BigDecimal shippingFee;
    private final LocalDateTime expectedDeliveryTime;
}
