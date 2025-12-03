package com.greenloop.order.query.projection;

import com.greenloop.order.command.event.OrderCreatedOfflineEvent;
import com.greenloop.order.dto.request.OrderItemOfflineRequest;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.eventhandling.EventHandler;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class OrderOfflineProjection {

    private final OrderRepository orderRepository;

    @EventHandler
    public void on(OrderCreatedOfflineEvent event) {
        log.info("Handling OrderCreatedOfflineEvent for orderId: {}", event.getOrderId());

        Order order = Order.builder()
                .orderId(event.getOrderId())
                .orderCode(event.getOrderCode())
                .customerId(event.getCustomerId())
                .eventId(event.getEventId())
                .voucherUserId(event.getVoucherUserId())
                .voucherCode(event.getVoucherCode())
                .discountAmount(event.getDiscountAmount())
                .guestName(event.getGuestName())
                .guestPhone(event.getGuestPhone())
                .isGuestPurchase(event.getIsGuestPurchase())
                .orderType(event.getOrderType())
                .subTotal(event.getSubTotal())
                .totalPrice(event.getTotalPrice())
                .orderStatus(event.getOrderStatus())
                .paymentStatus(event.getPaymentStatus())
                .paymentMethod(event.getPaymentMethod())
                .shippingAddress(null)
                .createdAt(LocalDateTime.now())
                .build();

        // Map OrderItems
        for (OrderItemOfflineRequest itemRequest : event.getOrderItems()) {
            OrderItem orderItem = OrderItem.builder()
                    .productId(itemRequest.getProductId())
                    .productName(itemRequest.getProductName())
                    .productImage(itemRequest.getProductImage())
                    .price(itemRequest.getPrice())
                    .build();

            order.getOrderItems().add(orderItem);
            orderItem.setOrder(order);
        }

        orderRepository.save(order);
        log.info("Order saved to read model: {}", event.getOrderCode());
    }

}
