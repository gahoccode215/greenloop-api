package com.greenloop.order.command.controller;

import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.request.UpdateOrderStatusRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Tag(name = "Order Command Controller", description = "Order Command Controller")
@Slf4j
public class OrderCommandController {

    private final CommandGateway commandGateway;



    @PatchMapping("/{orderId}/status")
    @Operation(summary = "Cập nhật trạng thái đơn hàng")
    public ResponseEntity<ApiResponseDTO<Object>> updateOrderStatus(
            @PathVariable String orderId,
            @Valid @RequestBody UpdateOrderStatusRequest request) {

        log.info("Updating order {} status to {}", orderId, request.getStatus());

        // Update order status
        UpdateOrderStatusCommand statusCommand = UpdateOrderStatusCommand.builder()
                .orderId(orderId)
                .orderStatus(request.getStatus())
                .build();

        commandGateway.sendAndWait(statusCommand);



        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Cập nhật trạng thái thành công",
                        null,
                        HttpStatus.OK
                )
        );
    }



}
