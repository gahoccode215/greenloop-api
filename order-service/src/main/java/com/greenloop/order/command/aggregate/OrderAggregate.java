package com.greenloop.order.command.aggregate;

import com.greenloop.order.command.*;
import com.greenloop.order.command.event.*;
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
import java.time.LocalDateTime;

@Aggregate
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

    // GoShip fields
    private String goshipShipmentId;
    private String goshipTrackingCode;
    private String carrier;
    private LocalDateTime expectedDeliveryTime;
    private String shippingStatus;

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
                command.getShippingFee(),
                command.getOrderItems(),
                command.getShippingAddress(),
                command.getPaymentStatus(),
                command.getPaymentMethod(),
                command.getPaymentOrderCode()
        ));
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
    public void on(OrderStatusUpdatedEvent event) {
        this.orderStatus = event.getOrderStatus();
    }

    @CommandHandler
    public void handle(CreateShipmentCommand command) {
        // Validation: Chỉ tạo shipment khi order ở trạng thái SHIPPED
        if (this.orderStatus != OrderStatus.SHIPPED) {
            throw new IllegalStateException(
                    "Cannot create shipment. Order must be in SHIPPED status. Current: " + this.orderStatus
            );
        }

        // Event này sẽ trigger Saga để gọi GoShip API
        AggregateLifecycle.apply(new ShipmentCreationRequestedEvent(
                command.getOrderId()
        ));
    }


    /**
     * Handler cho UpdateShippingInfoCommand
     * Command này được gọi sau khi GoShip API trả về thành công
     */
    @CommandHandler
    public void handle(UpdateShippingInfoCommand command) {
        AggregateLifecycle.apply(new ShipmentCreatedEvent(
                command.getOrderId(),
                command.getGoshipShipmentId(),
                command.getGoshipTrackingCode(),
                command.getCarrier(),
                command.getShippingFee(),
                command.getExpectedDeliveryTime()
        ));
    }

    @EventSourcingHandler
    public void on(ShipmentCreatedEvent event) {
        this.goshipShipmentId = event.getGoshipShipmentId();
        this.goshipTrackingCode = event.getGoshipTrackingCode();
        this.carrier = event.getCarrier();
        this.shippingFee = event.getShippingFee();
        this.expectedDeliveryTime = event.getExpectedDeliveryTime();
    }

    /**
     * Handler cho UpdateShippingStatusCommand (từ webhook)
     */
    @CommandHandler
    public void handle(UpdateShippingStatusCommand command) {
        AggregateLifecycle.apply(new ShippingStatusUpdatedEvent(
                command.getOrderId(),
                command.getShippingStatus()
        ));
    }

    @EventSourcingHandler
    public void on(ShippingStatusUpdatedEvent event) {
        this.shippingStatus = event.getShippingStatus();
    }
}
