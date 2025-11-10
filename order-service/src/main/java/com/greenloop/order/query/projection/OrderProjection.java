package com.greenloop.order.query.projection;

import com.greenloop.order.command.event.OrderCreatedEvent;
import com.greenloop.order.command.event.OrderStatusUpdatedEvent;
import com.greenloop.order.entity.Order;
import com.greenloop.order.service.OrderService;
import lombok.RequiredArgsConstructor;
import org.axonframework.config.ProcessingGroup;
import org.axonframework.eventhandling.EventHandler;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@ProcessingGroup("order-group")
public class OrderProjection {
    private final OrderService orderService;

    @EventHandler
    public void on(OrderCreatedEvent event){
        Order order = new Order();
        BeanUtils.copyProperties(event, order);
        orderService.createOrder(order);
    }

    @EventHandler
    public void on(OrderStatusUpdatedEvent event){
        Order order = new Order();
        BeanUtils.copyProperties(event, order);
        orderService.updateOrderStatus(order);
    }


}
