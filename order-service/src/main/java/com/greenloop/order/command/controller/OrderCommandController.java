package com.greenloop.order.command.controller;

import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.dto.ApiResponseDTO;
import com.greenloop.order.dto.request.CreateOrderRequest;
import com.greenloop.order.dto.request.UpdateOrderStatusRequest;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.util.OrderCodeGenerator;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Tag(name = "Order Command Controller", description = "Order Command Controller")
@Slf4j
public class OrderCommandController {

    private final CommandGateway commandGateway;

    @PostMapping
    public ResponseEntity<ApiResponseDTO<Map<String, String>>> createOrder(
            @Valid @RequestBody CreateOrderRequest request) {

        String orderId = UUID.randomUUID().toString();
        String orderCode = OrderCodeGenerator.generateOrderCode();

        CreateOrderCommand command = CreateOrderCommand.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(request.getCustomerId())
                .totalPrice(request.getTotalPrice())
                .orderStatus(OrderStatus.PENDING)
                .orderItems(request.getOrderItems())
                .shippingAddress(request.getShippingAddress())
                .build();

        commandGateway.sendAndWait(command);

        Map<String, String> responseData = Map.of(
                "orderId", orderId,
                "orderCode", orderCode
        );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDTO.success(
                        "Đơn hàng được tạo thành công",
                        responseData,
                        HttpStatus.CREATED
                ));
    }



    @PatchMapping("/{orderId}/status")
    public ResponseEntity<ApiResponseDTO<Object>> updateOrderStatus(
            @PathVariable String orderId,
            @Valid @RequestBody UpdateOrderStatusRequest request) {
        UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
                .orderId(orderId)
                .orderStatus(request.getStatus())
                .build();
        commandGateway.sendAndWait(command);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Cập nhật trạng thái thành công", null, HttpStatus.OK)
        );
    }


}

