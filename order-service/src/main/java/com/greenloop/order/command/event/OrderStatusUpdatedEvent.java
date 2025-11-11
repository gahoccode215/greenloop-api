package com.greenloop.order.command.event;

import com.greenloop.order.enums.OrderStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrderStatusUpdatedEvent {
    private  String orderId;
    private OrderStatus orderStatus;
}
