package com.greenloop.order.command.event;

import com.greenloop.order.enums.OrderStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class OrderStatusUpdatedEvent {
    private String orderId;
    private OrderStatus oldStatus;
    private OrderStatus newStatus;
    private String reason;

    private String goshipShipmentId;
    private String goshipTrackingUrl;
    private String carrier;
}
