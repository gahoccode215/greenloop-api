package com.greenloop.order.query.projection;

import com.greenloop.order.command.event.OrderCreatedEvent;
import com.greenloop.order.command.event.OrderStatusUpdatedEvent;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.service.OrderService;
import lombok.RequiredArgsConstructor;
import org.axonframework.config.ProcessingGroup;
import org.axonframework.eventhandling.EventHandler;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@ProcessingGroup("order-group")
public class OrderProjection {
    private final OrderService orderService;

    @EventHandler
    public void on(OrderCreatedEvent event){

        Order order = Order.builder()
                .orderId(event.getOrderId())
                .orderCode(event.getOrderCode())
                .customerId(event.getCustomerId())
                .totalPrice(event.getTotalPrice())
                .orderStatus(event.getOrderStatus())
                .build();

        if (event.getOrderItems() != null && !event.getOrderItems().isEmpty()) {
            List<OrderItem> items = event.getOrderItems().stream()
                    .map(itemReq -> OrderItem.builder()
                            .productId(itemReq.getProductId())
                            .quantity(itemReq.getQuantity())
                            .price(itemReq.getPrice())
                            .order(order)
                            .build())
                    .collect(Collectors.toList());
            order.setOrderItems(items);
        }

        orderService.createOrder(order);
    }

    @EventHandler
    public void on(OrderStatusUpdatedEvent event){
        orderService.updateOrderStatus(event.getOrderId(), event.getOrderStatus());
    }


}
