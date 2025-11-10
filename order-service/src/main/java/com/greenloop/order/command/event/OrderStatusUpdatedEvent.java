package com.greenloop.order.command.event;

import lombok.Data;

@Data
public class OrderStatusUpdatedEvent {
    private  String orderId;
    private  String status;
}
