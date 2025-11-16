package com.greenloop.order.command.aggregate;

import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.command.event.OrderCreatedEvent;
import com.greenloop.order.command.event.OrderStatusUpdatedEvent;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.InvalidOrderPriceException;
import com.greenloop.order.exception.InvalidOrderStatusException;
import org.axonframework.commandhandling.CommandHandler;
import org.axonframework.eventsourcing.EventSourcingHandler;
import org.axonframework.modelling.command.AggregateIdentifier;
import org.axonframework.modelling.command.AggregateLifecycle;
import org.axonframework.spring.stereotype.Aggregate;

import java.math.BigDecimal;

@Aggregate
public class OrderAggregate {

    @AggregateIdentifier
    private String orderId;
    private String orderCode;
    private Long customerId;
    private OrderStatus orderStatus;
    private BigDecimal totalPrice;
    private PaymentStatus paymentStatus;
    private PaymentMethod paymentMethod;
    private Long paymentOrderCode;

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
                command.getOrderStatus(),
                command.getTotalPrice(),
                command.getOrderItems(),
                command.getShippingAddress(),
                command.getPaymentStatus(),
                command.getPaymentMethod(),
                command.getPaymentOrderCode()
        ));
    }


    @EventSourcingHandler
    public void on(OrderCreatedEvent orderCreatedEvent){
        this.orderId = orderCreatedEvent.getOrderId();
        this.orderCode = orderCreatedEvent.getOrderCode();
        this.customerId = orderCreatedEvent.getCustomerId();
        this.orderStatus = orderCreatedEvent.getOrderStatus();
        this.totalPrice = orderCreatedEvent.getTotalPrice();
        this.paymentStatus = orderCreatedEvent.getPaymentStatus();
        this.paymentMethod = orderCreatedEvent.getPaymentMethod();
        this.paymentOrderCode = orderCreatedEvent.getPaymentOrderCode();
    }

    @CommandHandler
    public void handle(UpdateOrderStatusCommand command) {

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





}
