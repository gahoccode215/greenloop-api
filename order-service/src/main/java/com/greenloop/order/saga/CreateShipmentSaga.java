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
     * Event này được trigger khi Order chuyển sang SHIPPED
     */
    @StartSaga
    @SagaEventHandler(associationProperty = "orderId")
    public void handle(ShipmentCreationRequestedEvent event) {
        String orderId = event.getOrderId();

        log.info("[SAGA] Starting shipment creation for order: {}", orderId);

        try {
            // 1. Lấy thông tin order từ database
            Optional<Order> orderOpt = orderService.findById(orderId);

            if (orderOpt.isEmpty()) {
                log.error("[SAGA] Order not found: {}", orderId);
                handleShipmentCreationFailed(orderId, "Order not found");
                return;
            }

            Order order = orderOpt.get();

            // 2. Validate order data có đầy đủ để tạo shipment không
            if (!isValidForShipment(order)) {
                log.error("[SAGA] Order {} is not valid for shipment creation", orderId);
                handleShipmentCreationFailed(orderId, "Invalid order data for shipment");
                return;
            }

            // 3. Gọi GoShip API tạo shipment
            log.info("[SAGA] Calling GoShip API to create shipment for order: {}", orderId);
            ShipmentResponse shipmentResponse = goShipService.createShipment(order);

            log.info("[SAGA] GoShip returned shipment: ID={}, TrackingCode={}, Carrier={}",
                    shipmentResponse.getId(),
                    shipmentResponse.getTrackingCode(),
                    shipmentResponse.getCarrier());

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
        log.info("[SAGA] Shipment details - ID: {}, TrackingCode: {}, Carrier: {}",
                event.getGoshipShipmentId(),
                event.getGoshipTrackingCode(),
                event.getCarrier());
    }

    /**
     * Validate order có đủ thông tin để tạo shipment không
     */
    private boolean isValidForShipment(Order order) {
        if (order.getShippingAddress() == null) {
            log.error("[SAGA] Shipping address is null");
            return false;
        }

        // Validate receiver info
        if (order.getShippingAddress().getReceiverName() == null ||
                order.getShippingAddress().getReceiverPhone() == null ||
                order.getShippingAddress().getReceiverAddress() == null) {
            log.error("[SAGA] Receiver info is incomplete - Name: {}, Phone: {}, Address: {}",
                    order.getShippingAddress().getReceiverName(),
                    order.getShippingAddress().getReceiverPhone(),
                    order.getShippingAddress().getReceiverAddress());
            return false;
        }

        // Validate receiver location
        if (order.getShippingAddress().getReceiverCityId() == null ||
                order.getShippingAddress().getReceiverDistrictId() == null ||
                order.getShippingAddress().getReceiverWardCode() == null) {
            log.error("[SAGA] Receiver location is incomplete - Province: {}, District: {}, Ward: {}",
                    order.getShippingAddress().getReceiverCityId(),
                    order.getShippingAddress().getReceiverDistrictId(),
                    order.getShippingAddress().getReceiverWardCode());
            return false;
        }

        // Validate order items
        if (order.getOrderItems() == null || order.getOrderItems().isEmpty()) {
            log.error("[SAGA] Order has no items");
            return false;
        }

        return true;
    }

    /**
     * Xử lý khi tạo shipment thất bại
     * Order sẽ giữ nguyên trạng thái SHIPPED
     * Staff cần xử lý manual (check lại địa chỉ hoặc retry)
     */
    private void handleShipmentCreationFailed(String orderId, String reason) {
        log.error("[SAGA] ========================================");
        log.error("[SAGA] SHIPMENT CREATION FAILED");
        log.error("[SAGA] Order ID: {}", orderId);
        log.error("[SAGA] Reason: {}", reason);
        log.error("[SAGA] ========================================");

        // KHÔNG chuyển về CONFIRMED vì sẽ vi phạm transition rule
        // Order giữ nguyên trạng thái SHIPPED
        // Staff sẽ thấy order stuck ở SHIPPED và xử lý manual

        log.warn("[SAGA] Order {} remains in SHIPPED status. Manual intervention required.", orderId);
        log.warn("[SAGA] Staff should:");
        log.warn("[SAGA]   1. Check shipping address completeness");
        log.warn("[SAGA]   2. Verify GoShip API connection");
        log.warn("[SAGA]   3. Retry by calling POST /api/v1/orders/{}/shipment", orderId);

        // TODO: Gửi notification cho staff về việc tạo shipment thất bại
        // notificationService.notifyStaff(orderId, "Shipment creation failed: " + reason);

        // TODO: Lưu vào bảng failed_shipments để track và retry
        // failedShipmentRepository.save(new FailedShipment(orderId, reason, LocalDateTime.now()));
    }
}
