package com.greenloop.order.command.aggregate;

import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.command.event.OrderCreatedEvent;
import com.greenloop.order.command.event.OrderStatusUpdatedEvent;
import org.axonframework.commandhandling.CommandHandler;
import org.axonframework.eventsourcing.EventSourcingHandler;
import org.axonframework.modelling.command.AggregateIdentifier;
import org.axonframework.modelling.command.AggregateLifecycle;
import org.axonframework.spring.stereotype.Aggregate;
import org.springframework.beans.BeanUtils;

import java.math.BigDecimal;

@Aggregate
public class OrderAggregate {

    @AggregateIdentifier
    private String orderId;
    private String orderCode;
    private Long customerId;
    private String orderStatus;
    private BigDecimal totalPrice;

    public OrderAggregate() {
    }

    @CommandHandler
    public OrderAggregate(CreateOrderCommand createOrderCommand) {
        OrderCreatedEvent orderCreatedEvent = new OrderCreatedEvent();
        BeanUtils.copyProperties(createOrderCommand, orderCreatedEvent);
        AggregateLifecycle.apply(orderCreatedEvent);
    }

    @EventSourcingHandler
    public void on(OrderCreatedEvent orderCreatedEvent){
        this.orderId = orderCreatedEvent.getOrderId();
        this.orderCode = orderCreatedEvent.getOrderCode();
        this.customerId = orderCreatedEvent.getCustomerId();
        this.orderStatus = orderCreatedEvent.getOrderStatus();
        this.totalPrice = orderCreatedEvent.getTotalPrice();
    }

    @CommandHandler
    public void handle(UpdateOrderStatusCommand updateOrderStatusCommand){
        OrderStatusUpdatedEvent orderStatusUpdatedEvent = new OrderStatusUpdatedEvent();
        BeanUtils.copyProperties(updateOrderStatusCommand, orderStatusUpdatedEvent);
        AggregateLifecycle.apply(orderStatusUpdatedEvent);
    }

    @EventSourcingHandler
    public void on(OrderStatusUpdatedEvent orderStatusUpdatedEvent){
        this.orderStatus = orderStatusUpdatedEvent.getOrderStatus();
    }


}
