package com.greenloop.order.command.event;

import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.enums.OrderStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrderCreatedEvent {
    private  String orderId;
    private  String orderCode;
    private  Long customerId;
    private OrderStatus orderStatus;
    private  BigDecimal totalPrice;
    private List<OrderItemRequest> orderItems;
}
