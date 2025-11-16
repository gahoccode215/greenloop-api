package com.greenloop.order.command.event;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ShippingStatusUpdatedEvent {
    private String orderId;
    private String shippingStatus;
}
