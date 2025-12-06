//package com.greenloop.order.goship.service;
//
//import com.greenloop.order.command.event.ShippingStatusChangedEvent;
//import com.greenloop.order.entity.Order;
//import com.greenloop.order.enums.OrderStatus;
//import com.greenloop.order.exception.OrderNotFoundException;
//import com.greenloop.order.goship.dto.GoShipWebhookPayload;
//import com.greenloop.order.repository.OrderRepository;
//import com.greenloop.order.util.OrderStatusSyncMapper;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.context.ApplicationEventPublisher;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class GoShipWebhookService {
//
//    private final OrderRepository orderRepository;
//    private final ApplicationEventPublisher eventPublisher;
//
//    @Transactional
//    public void handleWebhook(GoShipWebhookPayload payload) {
//        String orderId = payload.getOrderId();
//        Order order = orderRepository.findById(orderId)
//                .orElseThrow(() -> new OrderNotFoundException(
//                        "Order not found for GoShip shipment: " + payload.getGcode()));
//        Integer oldShippingStatus = order.getShippingStatus();
//        OrderStatus oldOrderStatus = order.getOrderStatus();
//
//        Integer newShippingStatus;
//        newShippingStatus = Integer.parseInt(payload.getStatus());
//
//        if (payload.getTrackingUrl() != null) {
//            order.setGoshipTrackingUrl(payload.getTrackingUrl());
//        }
//        order.setShippingStatus(newShippingStatus);
//
//        OrderStatus targetOrderStatus = OrderStatusSyncMapper.getTargetOrderStatus(
//                newShippingStatus, oldOrderStatus);
//
//        if (targetOrderStatus != null && targetOrderStatus != oldOrderStatus) {
//            order.setOrderStatus(targetOrderStatus);
//        }
//        orderRepository.save(order);
//        eventPublisher.publishEvent(ShippingStatusChangedEvent.builder()
//                .orderId(orderId)
//                .oldStatus(oldShippingStatus)
//                .newStatus(newShippingStatus)
//                .statusText(payload.getStatusText())
//                .trackingUrl(payload.getTrackingUrl())
//                .carrier(order.getCarrier())
//                .build());
//
//    }
//}
