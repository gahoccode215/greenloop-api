package com.greenloop.order.goship.service;

import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.event.ProductStatusChangeEvent;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.OrderNotFoundException;
import com.greenloop.order.goship.dto.GoShipWebhookPayload;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.OrderService;
import com.greenloop.order.util.OrderStatusSyncMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoShipWebhookService {

    private final OrderRepository orderRepository;
    private final OrderService orderService;
    private final StreamBridge streamBridge;

    @Transactional
    public void handleWebhook(GoShipWebhookPayload payload) {
        String orderId = payload.getOrderId();
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(
                        "Order not found for GoShip shipment: " + payload.getGcode()));
        OrderStatus oldOrderStatus = order.getOrderStatus();

        Integer newShippingStatus = Integer.parseInt(payload.getStatus());

        if (payload.getTrackingUrl() != null) {
            order.setGoshipTrackingUrl(payload.getTrackingUrl());
        }
        order.setShippingStatus(newShippingStatus);

        OrderStatus targetOrderStatus = OrderStatusSyncMapper.getTargetOrderStatus(
                newShippingStatus, oldOrderStatus);

        if (targetOrderStatus != null && targetOrderStatus != oldOrderStatus) {
            order.setOrderStatus(targetOrderStatus);
        }
        handlePaymentStatusForDelivered(order, newShippingStatus, payload);

        order.setUpdatedAt(LocalDateTime.now());
        orderRepository.save(order);

        handleProductStatusChange(order, newShippingStatus, payload);
    }

    private void handleProductStatusChange(Order order, Integer goshipStatus, GoShipWebhookPayload payload) {
        String newProductStatus = null;
        String eventType = null;
        String oldProductStatus = null;

        switch (goshipStatus) {
            case 903: // Đã lấy hàng - xuất kho
            case 904: // Đang vận chuyển
                oldProductStatus = ProductStatusConstant.RESERVED;
                newProductStatus = ProductStatusConstant.IN_TRANSIT;
                eventType = "IN_TRANSIT";
                log.info("GoShip picked up order {} - Product: RESERVED -> IN_TRANSIT (Xuất kho)",
                        order.getOrderCode());
                break;

            case 917: // Thất lạc hàng
                oldProductStatus = ProductStatusConstant.IN_TRANSIT;
                newProductStatus = ProductStatusConstant.LOST;
                eventType = "LOST";
                log.error("Order {} products marked as LOST", order.getOrderCode());

                // Xử lý business cho LOST (COD/PayOS, thông báo, khiếu nại...)
                orderService.handleLostOrder(order.getOrderId(), payload.getMessage());
                break;

            default:
                // Các status khác không update product
                return;
        }

        if (newProductStatus != null) {
            publishProductStatusChangeEvent(order, oldProductStatus, newProductStatus, eventType);
        }
    }

    /**
     * Publish event để Product Service update status
     */
    private void publishProductStatusChangeEvent(Order order, String oldStatus, String newStatus, String eventType) {
        List<ProductStatusChangeEvent.ProductStatusChange> productChanges = order.getOrderItems().stream()
                .map(item -> ProductStatusChangeEvent.ProductStatusChange.builder()
                        .productId(item.getProductId())
                        .oldStatus(oldStatus)
                        .newStatus(newStatus)
                        .build())
                .collect(Collectors.toList());

        ProductStatusChangeEvent event = ProductStatusChangeEvent.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .eventType(eventType)
                .productChanges(productChanges)
                .timestamp(LocalDateTime.now())
                .build();

        streamBridge.send("productStatusChange-out-0", event);

        log.info("Published ProductStatusChangeEvent: {} -> {} for order {}",
                oldStatus, newStatus, order.getOrderCode());
    }

    private void handlePaymentStatusForDelivered(Order order, Integer goshipStatus, GoShipWebhookPayload payload) {
        // Status 905: Giao hàng thành công
        if (goshipStatus == 905) {
            // Nếu là COD và chưa thanh toán -> đánh dấu đã thanh toán
            if (order.getPaymentMethod() == PaymentMethod.COD
                    && order.getPaymentStatus() == PaymentStatus.UNPAID) {

                order.setPaymentStatus(PaymentStatus.PAID);

                log.info("COD Order {} marked as PAID after successful delivery. " +
                                "Customer paid: {}đ",
                        order.getOrderCode(),
                        payload.getCod());
            }
        }
    }
}
