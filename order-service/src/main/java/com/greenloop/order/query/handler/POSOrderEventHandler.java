package com.greenloop.order.query.handler;

import com.greenloop.order.command.event.POSOrderCreatedEvent;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.eventhandling.EventHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class POSOrderEventHandler {

    private final OrderRepository orderRepository;

    @EventHandler
    @Transactional
    public void on(POSOrderCreatedEvent event) {

        Order order = Order.builder()
                .orderId(event.getOrderId())
                .orderCode(event.getOrderCode())
                .orderType(event.getOrderType())
                .customerId(event.getCustomerId())
                .isGuestPurchase(event.getIsGuestPurchase())
                .eventLocationId(event.getEventLocationId())
                .posStaffId(event.getPosStaffId())
                .totalPrice(event.getTotalPrice())
                .shippingFee(java.math.BigDecimal.ZERO)
                .orderStatus(event.getOrderStatus())
                .paymentStatus(event.getPaymentStatus())
                .paymentMethod(event.getPaymentMethod())
                .paymentOrderCode(event.getPaymentOrderCode())
                .orderItems(new ArrayList<>())
                .build();

        if (event.getOrderItems() != null) {
            List<OrderItem> orderItems = event.getOrderItems().stream()
                    .map(item -> OrderItem.builder()
                            .productId(item.getProductId())
                            .quantity(item.getQuantity())
                            .price(item.getPrice())
                            .productName(item.getProductName())
                            .productImage(item.getProductImage())
                            .order(order)
                            .build())
                    .toList();

            order.setOrderItems(orderItems);
        }

        // Save to database
        orderRepository.save(order);

    }
}
