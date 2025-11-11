package com.greenloop.order.command.aggregate;

import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.command.SystemUpdateOrderStatusCommand;
import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.command.event.OrderCreatedEvent;
import com.greenloop.order.command.event.OrderStatusUpdatedEvent;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.exception.InvalidOrderPriceException;
import com.greenloop.order.exception.InvalidOrderStatusException;
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
    private OrderStatus orderStatus;
    private BigDecimal totalPrice;

    public OrderAggregate() {
    }

    @CommandHandler
    public OrderAggregate(CreateOrderCommand command) {
        if (command.getTotalPrice().compareTo(BigDecimal.ZERO) <= 0) {
            throw new InvalidOrderPriceException();
        }

        AggregateLifecycle.apply(new OrderCreatedEvent(
                command.getOrderId(),
                command.getOrderCode(),
                command.getCustomerId(),
                OrderStatus.PENDING,
                command.getTotalPrice(),
                command.getOrderItems(),
                command.getShippingAddress()
        ));
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
    public void handle(UpdateOrderStatusCommand command) {
        // Nếu là system update → skip validation
        if (command.getIsSystemUpdate() != null && command.getIsSystemUpdate()) {
            AggregateLifecycle.apply(new OrderStatusUpdatedEvent(
                    command.getOrderId(),
                    command.getOrderStatus()
            ));
            return;
        }

        if (!this.orderStatus.canTransitionTo(command.getOrderStatus())) {
            throw new InvalidOrderStatusException(
                    this.orderStatus.getDescription(),
                    command.getOrderStatus().getDescription()
            );
        }

        AggregateLifecycle.apply(new OrderStatusUpdatedEvent(
                command.getOrderId(),
                command.getOrderStatus()
        ));
    }



    @EventSourcingHandler
    public void on(OrderStatusUpdatedEvent orderStatusUpdatedEvent){
        this.orderStatus = orderStatusUpdatedEvent.getOrderStatus();
    }

    @CommandHandler
    public void handle(SystemUpdateOrderStatusCommand command) {
        // Không validate, cho phép update bất kỳ status nào
        AggregateLifecycle.apply(new OrderStatusUpdatedEvent(
                command.getOrderId(),
                command.getOrderStatus()
        ));
    }



}
