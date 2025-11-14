package com.greenloop.order.query.projection;

import com.greenloop.order.command.event.OrderCreatedEvent;
import com.greenloop.order.command.event.OrderStatusUpdatedEvent;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.entity.ShippingAddress;
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
    public void on(OrderCreatedEvent event) {
        Order order = Order.builder()
                .orderId(event.getOrderId())
                .orderCode(event.getOrderCode())
                .customerId(event.getCustomerId())
                .totalPrice(event.getTotalPrice())
                .orderStatus(event.getOrderStatus())
                .paymentStatus(event.getPaymentStatus())
                .paymentMethod(event.getPaymentMethod())
                .build();

        if (event.getShippingAddress() != null) {
            ShippingAddress shippingAddress = ShippingAddress.builder()
                    .receiverName(event.getShippingAddress().getReceiverName())
                    .receiverPhone(event.getShippingAddress().getReceiverPhone())
                    .receiverAddress(event.getShippingAddress().getAddress())
                    .receiverWardCode(event.getShippingAddress().getWardCode())
                    .receiverDistrictId(event.getShippingAddress().getDistrictId())
                    .receiverProvinceId(event.getShippingAddress().getProvinceId())
                    .note(event.getShippingAddress().getNote())
                    .build();
            order.setShippingAddress(shippingAddress);
        }

        // Map order items
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
