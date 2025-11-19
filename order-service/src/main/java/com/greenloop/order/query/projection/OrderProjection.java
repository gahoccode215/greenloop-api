package com.greenloop.order.query.projection;

import com.greenloop.order.command.event.*;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.entity.ShippingAddress;
import com.greenloop.order.service.OrderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.config.ProcessingGroup;
import org.axonframework.eventhandling.EventHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@ProcessingGroup("order-group")
@Slf4j
public class OrderProjection {

    private final OrderService orderService;

    @Value("${goship.default-warehouse.name}")
    private String warehouseName;

    @Value("${goship.default-warehouse.phone}")
    private String warehousePhone;

    @Value("${goship.default-warehouse.address}")
    private String warehouseAddress;

    @Value("${goship.default-warehouse.ward-code}")
    private Long warehouseWardCode;

    @Value("${goship.default-warehouse.ward-name}")
    private String warehouseWardName;

    @Value("${goship.default-warehouse.district-id}")
    private Integer warehouseDistrictId;

    @Value("${goship.default-warehouse.city-id}")
    private Integer warehouseCityId;

    @Value("${goship.default-warehouse.district-name}")
    private String warehouseDistrictName;

    @Value("${goship.default-warehouse.city-name}")
    private String warehouseCityName;

    @EventHandler
    public void on(OrderCreatedEvent event) {
        Order order = Order.builder()
                .orderId(event.getOrderId())
                .orderCode(event.getOrderCode())
                .customerId(event.getCustomerId())
                .totalPrice(event.getTotalPrice())
                .shippingFee(event.getShippingFee())
                .orderStatus(event.getOrderStatus())
                .paymentStatus(event.getPaymentStatus())
                .paymentMethod(event.getPaymentMethod())
                .paymentOrderCode(event.getPaymentOrderCode())
                .carrier(event.getCarrier())
                .expectedDeliveryTime(event.getExpectedDeliveryTime())
                .build();

        if (event.getShippingAddress() != null) {
            ShippingAddress shippingAddress = ShippingAddress.builder()
                    // Receiver info
                    .receiverName(event.getShippingAddress().getReceiverName())
                    .receiverPhone(event.getShippingAddress().getReceiverPhone())
                    .receiverAddress(event.getShippingAddress().getAddress())
                    .receiverWardCode(event.getShippingAddress().getWardCode())
                    .receiverWardName(event.getShippingAddress().getWard())
                    .receiverDistrictName(event.getShippingAddress().getDistrictName())
                    .receiverCityName(event.getShippingAddress().getCityName())
                    .receiverDistrictId(event.getShippingAddress().getDistrictId())
                    .receiverCityId(event.getShippingAddress().getCityId())
                    .note(event.getShippingAddress().getNote())
                    .warehouseName(warehouseName)
                    .warehousePhone(warehousePhone)
                    .warehouseAddress(warehouseAddress)
                    .warehouseWardCode(warehouseWardCode)
                    .warehouseWardName(warehouseWardName)
                    .warehouseDistrictId(warehouseDistrictId)
                    .warehouseDistrictName(warehouseDistrictName)
                    .warehouseCityName(warehouseCityName)
                    .warehouseCityId(warehouseCityId)
                    .build();

            order.setShippingAddress(shippingAddress);

            log.debug("Shipping address set - Receiver: {}, Warehouse: {}",
                    shippingAddress.getReceiverName(),
                    shippingAddress.getWarehouseName());
        }

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
        log.info("Order created: {}", event.getOrderCode());
    }

    @EventHandler
    public void on(OrderStatusUpdatedEvent event) {
        orderService.updateOrderStatus(event.getOrderId(), event.getOrderStatus());
        log.info("Order {} status updated to {}", event.getOrderId(), event.getOrderStatus());
    }



}
