package com.greenloop.order.saga;

import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.command.UpdateShippingInfoCommand;
import com.greenloop.order.command.event.ShipmentCreatedEvent;
import com.greenloop.order.command.event.ShipmentCreationRequestedEvent;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.goship.dto.ShipmentResponse;
import com.greenloop.order.goship.service.GoShipService;
import com.greenloop.order.service.OrderService;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.axonframework.modelling.saga.EndSaga;
import org.axonframework.modelling.saga.SagaEventHandler;
import org.axonframework.modelling.saga.StartSaga;
import org.axonframework.spring.stereotype.Saga;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Optional;

@Saga
@Slf4j
public class CreateShipmentSaga {

    @Autowired
    private transient CommandGateway commandGateway;

    @Autowired
    private transient GoShipService goShipService;

    @Autowired
    private transient OrderService orderService;

    /**
     * Saga bắt đầu khi nhận ShipmentCreationRequestedEvent
     * Event này được trigger khi Order chuyển sang PROCESSING
     */
    @StartSaga
    @SagaEventHandler(associationProperty = "orderId")
    public void handle(ShipmentCreationRequestedEvent event) {
        String orderId = event.getOrderId();

        log.info("[SAGA] Starting shipment creation for order: {}", orderId);

        try {
            // 1. Lấy thông tin order
            Optional<Order> orderOpt = orderService.findById(orderId);

            if (orderOpt.isEmpty()) {
                log.error("[SAGA] Order not found: {}", orderId);
                handleShipmentCreationFailed(orderId, "Order not found");
                return;
            }

            Order order = orderOpt.get();

            // 2. Validate order data
            if (!isValidForShipment(order)) {
                log.error("[SAGA] Order {} is not valid for shipment creation", orderId);
                handleShipmentCreationFailed(orderId, "Invalid order data for shipment");
                return;
            }

            // 3. Gọi GoShip API tạo shipment
            log.info("[SAGA] Calling GoShip API to create shipment for order: {}", orderId);
            ShipmentResponse shipmentResponse = goShipService.createShipment(order);

            // 4. Gửi command để update shipping info vào aggregate
            UpdateShippingInfoCommand updateCommand = UpdateShippingInfoCommand.builder()
                    .orderId(orderId)
                    .goshipShipmentId(shipmentResponse.getId())
                    .goshipTrackingCode(shipmentResponse.getTrackingCode())
                    .carrier(shipmentResponse.getCarrier())
                    .shippingFee(shipmentResponse.getTotalFee())
                    .expectedDeliveryTime(shipmentResponse.getExpectedDeliveryTime())
                    .build();

            commandGateway.sendAndWait(updateCommand);

            log.info("[SAGA] Successfully created shipment {} for order: {}",
                    shipmentResponse.getTrackingCode(), orderId);

            // 5. Chuyển order sang trạng thái SHIPPING
            UpdateOrderStatusCommand statusCommand = UpdateOrderStatusCommand.builder()
                    .orderId(orderId)
                    .orderStatus(OrderStatus.SHIPPING)
                    .build();

            commandGateway.sendAndWait(statusCommand);

            log.info("[SAGA] Order {} moved to SHIPPING status", orderId);

        } catch (Exception e) {
            log.error("[SAGA] Failed to create shipment for order {}: {}", orderId, e.getMessage(), e);
            handleShipmentCreationFailed(orderId, e.getMessage());
        }
    }

    /**
     * Saga kết thúc khi shipment được tạo thành công
     */
    @EndSaga
    @SagaEventHandler(associationProperty = "orderId")
    public void handle(ShipmentCreatedEvent event) {
        log.info("[SAGA] Shipment creation saga completed for order: {}", event.getOrderId());
    }

    /**
     * Validate order có đủ thông tin để tạo shipment không
     */
    private boolean isValidForShipment(Order order) {
        if (order.getShippingAddress() == null) {
            log.error("Shipping address is null");
            return false;
        }

        if (order.getShippingAddress().getReceiverName() == null ||
                order.getShippingAddress().getReceiverPhone() == null ||
                order.getShippingAddress().getReceiverAddress() == null) {
            log.error("Shipping address is incomplete");
            return false;
        }

        if (order.getShippingAddress().getReceiverProvinceId() == null ||
                order.getShippingAddress().getReceiverDistrictId() == null ||
                order.getShippingAddress().getReceiverWardCode() == null) {
            log.error("Shipping address location is incomplete");
            return false;
        }

        if (order.getOrderItems() == null || order.getOrderItems().isEmpty()) {
            log.error("Order has no items");
            return false;
        }

        return true;
    }

    /**
     * Xử lý khi tạo shipment thất bại
     * Có thể chuyển về CONFIRMED hoặc đánh dấu cần xử lý manual
     */
    private void handleShipmentCreationFailed(String orderId, String reason) {
        log.error("[SAGA] Shipment creation failed for order {}: {}", orderId, reason);

        // Option 1: Chuyển về CONFIRMED để staff xử lý lại
        UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                .orderId(orderId)
                .orderStatus(OrderStatus.CONFIRMED)
                .build();

        commandGateway.sendAndWait(command);

        // TODO: Gửi notification cho staff về việc tạo shipment thất bại
        log.info("[SAGA] Order {} reverted to CONFIRMED status for manual handling", orderId);
    }
}
