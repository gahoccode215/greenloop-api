package com.greenloop.order.goship.controller;

import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.command.UpdateShippingStatusCommand;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.goship.dto.GoShipWebhookPayload;
import com.greenloop.order.repository.OrderRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

/**
 * GoShip Webhook Controller
 *
 * Nhận callback từ GoShip khi trạng thái shipment thay đổi
 *
 * Webhook Events:
 * - shipment.created: Shipment được tạo thành công
 * - shipment.updated: Trạng thái shipment thay đổi
 * - shipment.delivered: Giao hàng thành công
 * - shipment.failed: Giao hàng thất bại
 *
 * Flow:
 * 1. GoShip gửi webhook với shipment status
 * 2. Tìm order theo shipmentId
 * 3. Update shipping_status (internal tracking)
 * 4. Map GoShip status → OrderStatus
 * 5. Update order status nếu cần
 * 6. Send notification cho customer (TODO)
 */
@RestController
@RequestMapping("/api/v1/webhooks/goship")
@RequiredArgsConstructor
@Tag(name = "GoShip Webhook", description = "Nhận callback từ GoShip khi trạng thái shipment thay đổi")
@Slf4j
public class GoShipWebhookController {

    private final CommandGateway commandGateway;
    private final OrderRepository orderRepository;

    @PostMapping("/shipment-status")
    @Operation(summary = "GoShip Webhook - Cập nhật trạng thái shipment")
    public ResponseEntity<ApiResponseDTO<Object>> handleShipmentStatus(
            @RequestBody GoShipWebhookPayload payload,
            @RequestHeader(value = "X-GoShip-Signature", required = false) String signature) {

        try {
            log.info("========================================");
            log.info("Received GoShip webhook");
            log.info("Event: {}", payload.getEvent());
            log.info("ShipmentId: {}", payload.getData().getId());
            log.info("Status: {}", payload.getData().getStatus());
            log.info("Carrier: {}", payload.getData().getCarrier());
            log.info("========================================");

            // TODO: Verify webhook signature để đảm bảo request từ GoShip
            // if (!verifySignature(payload, signature)) {
            //     log.error("Invalid webhook signature");
            //     return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            //             ApiResponseDTO.error("Invalid signature", HttpStatus.UNAUTHORIZED, "/api/v1/webhooks/goship/shipment-status")
            //     );
            // }

            // Tìm order theo shipmentId
            String shipmentId = payload.getData().getId();
            Optional<Order> orderOpt = orderRepository.findByGoshipShipmentId(shipmentId);

            if (orderOpt.isEmpty()) {
                log.warn("Order not found for shipmentId: {}", shipmentId);
                return ResponseEntity.ok(
                        ApiResponseDTO.success("Shipment not found", null, HttpStatus.OK)
                );
            }

            Order order = orderOpt.get();
            String orderId = order.getOrderId();
            String goshipStatus = payload.getData().getStatus();

            log.info("Found order: {} - Current status: {}", orderId, order.getOrderStatus());

            // Update shipping status (internal tracking - lưu raw status từ GoShip)
            UpdateShippingStatusCommand statusCommand = UpdateShippingStatusCommand.builder()
                    .orderId(orderId)
                    .shippingStatus(goshipStatus)
                    .build();

            commandGateway.sendAndWait(statusCommand);

            log.info("Updated shipping_status for order {}: {}", orderId, goshipStatus);

            // Map GoShip status to OrderStatus và update nếu cần
            OrderStatus newOrderStatus = mapGoShipStatusToOrderStatus(goshipStatus);

            if (newOrderStatus != null) {
                if (shouldUpdateOrderStatus(order.getOrderStatus(), newOrderStatus)) {
                    UpdateOrderStatusCommand orderStatusCommand = UpdateOrderStatusCommand.builder()
                            .orderId(orderId)
                            .orderStatus(newOrderStatus)
                            .build();

                    commandGateway.sendAndWait(orderStatusCommand);

                    log.info("✅ Updated order {} status: {} → {}",
                            orderId, order.getOrderStatus(), newOrderStatus);
                } else {
                    log.info("ℹ️ Order {} already in status {}, no update needed",
                            orderId, order.getOrderStatus());
                }
            } else {
                log.debug("GoShip status '{}' does not require order status change", goshipStatus);
            }

            // TODO: Gửi notification cho customer về trạng thái đơn hàng
            // notificationService.notifyCustomer(order.getCustomerId(), orderId, newOrderStatus);

            log.info("========================================");
            log.info("Webhook processed successfully for order: {}", orderId);
            log.info("========================================");

            return ResponseEntity.ok(
                    ApiResponseDTO.success("Webhook processed successfully", null, HttpStatus.OK)
            );

        } catch (Exception e) {
            log.error("========================================");
            log.error("Error processing GoShip webhook: {}", e.getMessage(), e);
            log.error("========================================");

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Error processing webhook: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            "/api/v1/webhooks/goship/shipment-status"
                    )
            );
        }
    }

    /**
     * Map GoShip shipping status sang OrderStatus
     *
     * GoShip Status Reference:
     * - pending: Chờ shipper lấy hàng
     * - picking: Shipper đang đến lấy hàng
     * - picked_up: Đã lấy hàng
     * - in_transit: Đang vận chuyển
     * - sorting: Đang phân loại tại hub
     * - delivering: Shipper đang giao
     * - out_for_delivery: Đã ra giao hàng
     * - delivered: Đã giao thành công
     * - failed: Giao hàng thất bại
     * - delivery_failed: Không giao được
     * - returning: Đang hoàn trả
     * - return_to_sender: Đang trả về người gửi
     * - returned: Đã hoàn trả
     * - cancelled: Đơn bị hủy
     */
    private OrderStatus mapGoShipStatusToOrderStatus(String goshipStatus) {
        if (goshipStatus == null) {
            return null;
        }

        OrderStatus mapped = switch (goshipStatus.toLowerCase()) {
            // GoShip picking stages - Giữ nguyên SHIPPING
            case "pending", "picking" -> null;
            case "picked_up" -> OrderStatus.SHIPPING;

            // GoShip delivery stages
            case "in_transit", "sorting" -> OrderStatus.SHIPPING;
            case "delivering", "out_for_delivery" -> OrderStatus.DELIVERING;
            case "delivered" -> OrderStatus.DELIVERED;

            // GoShip failure/return stages
            case "failed", "delivery_failed" -> OrderStatus.DELIVERY_FAILED;
            case "returning", "return_to_sender" -> OrderStatus.RETURNING;
            case "returned" -> OrderStatus.RETURNED;
            case "cancelled" -> OrderStatus.CANCELLED;

            default -> {
                log.debug("Unknown GoShip status: {}", goshipStatus);
                yield null;
            }
        };

        log.debug("Mapping GoShip status '{}' → OrderStatus '{}'", goshipStatus, mapped);
        return mapped;
    }

    /**
     * Check xem có nên update order status không
     * Tránh update duplicate hoặc vi phạm transition rules
     */
    private boolean shouldUpdateOrderStatus(OrderStatus currentStatus, OrderStatus newStatus) {
        // Nếu status giống nhau thì không cần update
        if (currentStatus == newStatus) {
            log.debug("Status unchanged: {}", currentStatus);
            return false;
        }

        // Check xem transition có hợp lệ không
        if (!currentStatus.canTransitionTo(newStatus)) {
            log.warn("⚠️ Invalid transition: {} → {} (not allowed by business rules)",
                    currentStatus, newStatus);
            return false;
        }

        log.debug("✅ Valid transition: {} → {}", currentStatus, newStatus);
        return true;
    }

    /**
     * Verify webhook signature từ GoShip (security best practice)
     *
     * TODO: Implement theo docs GoShip
     *
     * Example implementation:
     * 1. Lấy webhook secret từ GoShip dashboard
     * 2. Tính HMAC SHA256 của request body với secret
     * 3. So sánh với X-GoShip-Signature header
     *
     * @param payload Webhook payload
     * @param signature Signature từ header
     * @return true nếu signature hợp lệ
     */
    private boolean verifySignature(GoShipWebhookPayload payload, String signature) {
        // Implement webhook signature verification
        //
        // String secretKey = goShipProperties.getWebhookSecret();
        // String calculatedSignature = HmacUtils.hmacSha256Hex(secretKey, objectMapper.writeValueAsString(payload));
        // return calculatedSignature.equals(signature);

        return true; // Tạm thời return true
    }
}
