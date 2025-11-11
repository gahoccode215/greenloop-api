package com.greenloop.order.ghn.controller;

import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.dto.ApiResponseDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.ghn.dto.webhook.GHNWebhookRequest;
import com.greenloop.order.ghn.mapper.GHNStatusMapper;
import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/webhooks/ghn")
@RequiredArgsConstructor
@Slf4j
public class GHNWebhookController {

    private final CommandGateway commandGateway;
    private final OrderRepository orderRepository;

    /**
     * Endpoint nhận webhook từ GHN khi trạng thái đơn hàng thay đổi
     * GHN sẽ gọi API này mỗi khi shipper cập nhật status
     */
    @PostMapping("/order-status")
    public ResponseEntity<ApiResponseDTO<Object>> handleOrderStatusUpdate(
            @RequestBody GHNWebhookRequest request) {

        log.info("Received GHN webhook: orderCode={}, status={}",
                request.getOrderCode(), request.getStatus());

        try {
            // 1. Tìm order theo GHN order code
            Order order = orderRepository.findByGhnOrderCode(request.getOrderCode())
                    .orElseThrow(() -> new RuntimeException("Order not found with GHN code: " + request.getOrderCode()));

            // 2. Update shipping status (trạng thái GHN)
            order.setShippingStatus(request.getStatus());
            orderRepository.save(order);

            // 3. Map GHN status sang OrderStatus
            OrderStatus newOrderStatus = GHNStatusMapper.mapToOrderStatus(request.getStatus());

            // 4. Nếu map được và khác status hiện tại → update order status
            if (newOrderStatus != null && newOrderStatus != order.getOrderStatus()) {
                log.info("Auto updating order {} status from {} to {} based on GHN webhook",
                        order.getOrderId(), order.getOrderStatus(), newOrderStatus);

                UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                        .orderId(order.getOrderId())
                        .orderStatus(newOrderStatus)
                        .isSystemUpdate(true)  // System update, skip validation
                        .build();

                commandGateway.sendAndWait(command);
            }

            return ResponseEntity.ok(ApiResponseDTO.success(
                    "Webhook processed successfully",
                    null,
                    HttpStatus.OK
            ));

        } catch (Exception e) {
            log.error("Failed to process GHN webhook", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error(
                            "Webhook processing failed: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            "/webhooks/ghn"));
        }
    }
}
