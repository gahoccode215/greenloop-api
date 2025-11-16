package com.greenloop.order.command.event;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ShipmentCreatedEvent {
    private String orderId;
    private String goshipShipmentId;
    private String goshipTrackingCode;
    private String carrier;
    private BigDecimal shippingFee;
    private LocalDateTime expectedDeliveryTime;
}
