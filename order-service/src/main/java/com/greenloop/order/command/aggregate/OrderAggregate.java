package com.greenloop.order.command.aggregate;

import com.greenloop.order.command.*;
import com.greenloop.order.command.event.*;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.InvalidOrderPriceException;
import com.greenloop.order.exception.InvalidOrderStatusException;
import com.greenloop.order.exception.OrderNotCancellableException;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.CommandHandler;
import org.axonframework.eventsourcing.EventSourcingHandler;
import org.axonframework.modelling.command.AggregateIdentifier;
import org.axonframework.modelling.command.AggregateLifecycle;
import org.axonframework.spring.stereotype.Aggregate;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Aggregate
@NoArgsConstructor
@Slf4j
public class OrderAggregate {

    @AggregateIdentifier
    private String orderId;
    private String orderCode;
    private Long customerId;
    private OrderStatus orderStatus;
    private BigDecimal totalPrice;
    private BigDecimal shippingFee;
    private PaymentStatus paymentStatus;
    private PaymentMethod paymentMethod;
    private Long paymentOrderCode;
    private String goshipShipmentId;
    private String goshipTrackingCode;
    private String carrier;
    private LocalDateTime expectedDeliveryTime;
    private Integer shippingStatus;
    private String parcelWeight;
    private String parcelWidth;
    private String parcelHeight;
    private String parcelLength;
    private String reason;

    @CommandHandler
    public OrderAggregate(CreateOrderCommand command) {
        if (command.getTotalPrice().compareTo(BigDecimal.ZERO) <= 0) {
            throw new InvalidOrderPriceException();
        }
        AggregateLifecycle.apply(OrderCreatedEvent.builder()
                .orderId(command.getOrderId())
                .orderCode(command.getOrderCode())
                .customerId(command.getCustomerId())
                .totalPrice(command.getTotalPrice())
                .shippingFee(command.getShippingFee())
                .orderStatus(command.getOrderStatus())
                .paymentStatus(command.getPaymentStatus())
                .paymentMethod(command.getPaymentMethod())
                .paymentOrderCode(command.getPaymentOrderCode())
                .orderItems(command.getOrderItems())
                .shippingAddress(command.getShippingAddress())
                .selectedRateId(command.getSelectedRateId())
                .carrier(command.getCarrier())
                .expectedDeliveryTime(command.getExpectedDeliveryTime())
                .parcelWeight(command.getParcelWeight())
                .parcelWidth(command.getParcelWidth())
                .parcelHeight(command.getParcelHeight())
                .parcelLength(command.getParcelLength())
                .shippingStatus(command.getShippingStatus())
                .build());
    }

    @EventSourcingHandler
    public void on(OrderCreatedEvent event) {
        this.orderId = event.getOrderId();
        this.orderCode = event.getOrderCode();
        this.customerId = event.getCustomerId();
        this.orderStatus = event.getOrderStatus();
        this.totalPrice = event.getTotalPrice();
        this.shippingFee = event.getShippingFee();
        this.paymentStatus = event.getPaymentStatus();
        this.paymentMethod = event.getPaymentMethod();
        this.paymentOrderCode = event.getPaymentOrderCode();
        this.carrier = event.getCarrier();
        this.expectedDeliveryTime = event.getExpectedDeliveryTime();
        this.parcelWeight = event.getParcelWeight();
        this.parcelWidth = event.getParcelWidth();
        this.parcelHeight = event.getParcelHeight();
        this.parcelLength = event.getParcelLength();
        this.shippingStatus = event.getShippingStatus();
    }

    @CommandHandler
    public void handle(UpdateOrderStatusCommand command) {
        if (!this.orderStatus.canTransitionTo(command.getNewStatus())) {
            throw new InvalidOrderStatusException(
                    this.orderStatus.getDescription(),
                    command.getNewStatus().getDescription()
            );
        }
        if (command.getNewStatus() == OrderStatus.CANCELLED
                && !this.orderStatus.isCancellable()) {
            throw new OrderNotCancellableException(this.orderStatus.getDescription());
        }
        AggregateLifecycle.apply(OrderStatusUpdatedEvent.builder()
                .orderId(command.getOrderId())
                .oldStatus(this.orderStatus)
                .newStatus(command.getNewStatus())
                .reason(command.getReason())
                .goshipShipmentId(command.getGoshipShipmentId())
                .goshipTrackingUrl(command.getGoshipTrackingCode())
                .carrier(command.getCarrier())
                .build());
    }

    @EventSourcingHandler
    public void on(OrderStatusUpdatedEvent event) {
        this.orderStatus = event.getNewStatus();
        this.reason = event.getReason();
        if (event.getGoshipShipmentId() != null) {
            this.goshipShipmentId = event.getGoshipShipmentId();
            this.goshipTrackingCode = event.getGoshipTrackingUrl();
            this.carrier = event.getCarrier();
        }
    }

}
