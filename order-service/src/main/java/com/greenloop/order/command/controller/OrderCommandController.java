package com.greenloop.order.command.controller;

import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.dto.request.CreateShipmentRequestDTO;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.ShipmentInfoResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.goship.dto.CreateShipmentResponse;
import com.greenloop.order.goship.service.GoShipService;
import com.greenloop.order.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Order Command", description = "Order command APIs")
public class OrderCommandController {

    private final CommandGateway commandGateway;
    private final OrderService orderService;
    private final GoShipService goShipService;

    @Operation(summary = "Confirm order (Staff)")
    @PostMapping("/{orderId}/confirm")
    public ResponseEntity<ApiResponseDTO<Void>> confirmOrder(@PathVariable String orderId, @RequestParam(required = false) String reason) {
        UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                .orderId(orderId)
                .newStatus(OrderStatus.CONFIRMED)
                .reason(reason)
                .build();
        commandGateway.sendAndWait(command);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Xác nhận đơn hàng thành công", null, HttpStatus.OK)
        );
    }

    @Operation(summary = "Start processing order (Staff)")
    @PostMapping("/{orderId}/process")
    public ResponseEntity<ApiResponseDTO<Void>> processOrder(@PathVariable String orderId,
                                                             @RequestParam(required = false) String reason) {
        UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                .orderId(orderId)
                .newStatus(OrderStatus.PROCESSING)
                .reason(reason)
                .build();
        commandGateway.sendAndWait(command);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Bắt đầu xử lý đơn hàng thành công", null, HttpStatus.OK)
        );
    }

    @Operation(summary = "Create shipment with custom info (Staff)")
    @PostMapping("/{orderId}/ship")
    public ResponseEntity<ApiResponseDTO<ShipmentInfoResponse>> shipOrder(
            @PathVariable String orderId,
            @Valid @RequestBody CreateShipmentRequestDTO request) {

        CreateShipmentResponse shipmentResponse = goShipService.createShipmentForOrder(orderId, request);

        UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                .orderId(orderId)
                .newStatus(OrderStatus.READY_TO_SHIP)
                .reason(request.getReason())
                .goshipShipmentId(shipmentResponse.getId())
                .goshipTrackingCode(shipmentResponse.getTrackingNumber())
                .carrier(shipmentResponse.getCarrier())
                .build();

        commandGateway.sendAndWait(command);

        ShipmentInfoResponse response = ShipmentInfoResponse.builder()
                .shipmentId(shipmentResponse.getId())
                .trackingNumber(shipmentResponse.getTrackingNumber())
                .carrier(shipmentResponse.getCarrier())
                .fee(shipmentResponse.getFee())
                .createdAt(shipmentResponse.getCreatedAt())
                .build();

        return ResponseEntity.ok(
                ApiResponseDTO.success("Tạo vận đơn thành công", response, HttpStatus.OK)
        );
    }


    @Operation(summary = "Complete order)")
    @PostMapping("/{orderId}/complete")
    public ResponseEntity<ApiResponseDTO<Void>> completeOrder(@PathVariable String orderId,
    @RequestParam(required = false) String reason) {
        UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                .orderId(orderId)
                .newStatus(OrderStatus.COMPLETED)
                .reason(reason)
                .build();
        commandGateway.sendAndWait(command);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Hoàn thành đơn hàng thành công", null, HttpStatus.OK)
        );
    }

    @Operation(summary = "Cancel order (Customer/Staff)")
    @PostMapping("/{orderId}/cancel")
    public ResponseEntity<ApiResponseDTO<Void>> cancelOrder(
            @PathVariable String orderId,
            @RequestParam(required = false) String reason) {
        Order order = orderService.getOrderEntityById(orderId);
        if (order.getGoshipShipmentId() != null) {
            goShipService.cancelShipment(order.getGoshipShipmentId());
        }
        UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                .orderId(orderId)
                .newStatus(OrderStatus.CANCELLED)
                .reason(reason)
                .build();
        commandGateway.sendAndWait(command);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Hủy đơn hàng thành công", null, HttpStatus.OK)
        );
    }
}
