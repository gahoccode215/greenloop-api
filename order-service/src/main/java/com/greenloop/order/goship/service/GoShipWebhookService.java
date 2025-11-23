package com.greenloop.order.goship.service;

import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.exception.OrderNotFoundException;
import com.greenloop.order.goship.dto.GoShipWebhookPayload;
import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoShipWebhookService {

    private final OrderRepository orderRepository;
    private final CommandGateway commandGateway;

    @Transactional
    public void handleWebhook(GoShipWebhookPayload payload) {
        log.info("Processing GoShip webhook - GCode: {}, Status: {}, OrderId: {}",
                payload.getGcode(), payload.getStatus(), payload.getOrderId());

        // Find order by order code (order_id from webhook)
        Order order = orderRepository.findByOrderCode(payload.getOrderId())
                .orElseThrow(() -> new OrderNotFoundException(
                        "Order not found: " + payload.getOrderId()));

        // Update GoShip shipment ID if not set
        if ((order.getGoshipShipmentId() == null || order.getGoshipShipmentId().isBlank())
                && payload.getGcode() != null
                && !"NULL".equalsIgnoreCase(payload.getGcode())) {
            order.setGoshipShipmentId(payload.getGcode());
            log.info("Updated GoShip shipment ID for order {}: {}",
                    order.getOrderCode(), payload.getGcode());
        }

        // Update tracking code if provided and different
        if (payload.getCode() != null
                && !"NULL".equalsIgnoreCase(payload.getCode())
                && !payload.getCode().equals(order.getGoshipTrackingCode())) {

            order.setGoshipTrackingCode(payload.getCode());
            log.info("Updated tracking code for order {}: {}",
                    order.getOrderCode(), payload.getCode());
        }

        // Update shipping status
        if (payload.getStatus() != null) {
            order.setShippingStatus(payload.getStatus());
        }

        // Handle special cases
        if (payload.getIsReturn() != null && payload.getIsReturn() == 1) {
            handleReturnOrder(order, payload);
        } else if (payload.getIsLost() != null && payload.getIsLost() == 1) {
            handleLostOrder(order, payload);
        } else {
            // Normal status update
            OrderStatus newOrderStatus = mapGoShipStatusToOrderStatus(payload.getStatus());
            if (newOrderStatus != null && newOrderStatus != order.getOrderStatus()) {
                UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                        .orderId(order.getOrderId())
                        .newStatus(newOrderStatus)
                        .reason(String.format("GoShip webhook: %s - %s",
                                payload.getStatusText(), payload.getMessage()))
                        .build();

                commandGateway.sendAndWait(command);

                log.info("Updated order {} status from {} to {} (GoShip status: {})",
                        order.getOrderCode(), order.getOrderStatus(), newOrderStatus, payload.getStatus());
            } else {
                log.info("Order {} status kept as {} (GoShip status: {})",
                        order.getOrderCode(), order.getOrderStatus(), payload.getStatus());
            }
        }

        orderRepository.save(order);
    }

    private void handleReturnOrder(Order order, GoShipWebhookPayload payload) {
        log.warn("Order {} is being returned - Status: {}", order.getOrderCode(), payload.getStatusText());

        UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                .orderId(order.getOrderId())
                .newStatus(OrderStatus.RETURNING)
                .reason("Đơn hàng đang được hoàn trả: " + payload.getMessage())
                .build();

        commandGateway.sendAndWait(command);
    }

    private void handleLostOrder(Order order, GoShipWebhookPayload payload) {
        log.error("Order {} is LOST - Status: {}", order.getOrderCode(), payload.getStatusText());

        UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                .orderId(order.getOrderId())
                .newStatus(OrderStatus.CANCELLED)
                .reason("Đơn hàng bị thất lạc: " + payload.getMessage())
                .build();

        commandGateway.sendAndWait(command);
    }

    /**
     * Map GoShip status code to Order status
     */
    private OrderStatus mapGoShipStatusToOrderStatus(String goshipStatus) {
        if (goshipStatus == null) {
            return null;
        }

        switch (goshipStatus) {
            // Awaiting pickup - keep SHIPPED
            case "901":  // Chờ lấy hàng
            case "902":  // Đã lấy hàng
                return null;

            // In transit - change to DELIVERING
            case "903":  // Nhập kho
            case "904":  // Xuất kho
            case "906":  // Đang giao hàng
                return OrderStatus.DELIVERING;

            // Delivered
            case "905":  // Giao hàng thành công
                return OrderStatus.DELIVERED;

            // Failed delivery
            case "908":  // Giao hàng không thành công
            case "910":  // Hẹn giao lại
                return OrderStatus.DELIVERY_FAILED;

            // Return
            case "911":  // Đang hoàn hàng
                return OrderStatus.RETURNING;
            case "912":  // Đã hoàn hàng
                return OrderStatus.RETURNED;

            // Cancelled
            case "913":  // Đơn hủy
                return OrderStatus.CANCELLED;

            default:
                log.warn("Unknown GoShip status code: {}", goshipStatus);
                return null;
        }
    }
}
