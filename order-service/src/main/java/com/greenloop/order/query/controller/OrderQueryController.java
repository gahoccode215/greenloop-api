package com.greenloop.order.query.controller;

import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.goship.dto.ShipmentResponse;
import com.greenloop.order.goship.service.GoShipService;
import com.greenloop.order.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Tag(name = "Order Query Controller")
@Slf4j
public class OrderQueryController {

    private final OrderService orderService;
    private final GoShipService goShipService;

    @GetMapping("/{orderId}")
    @Operation(summary = "Lấy thông tin đơn hàng")
    public ResponseEntity<ApiResponseDTO<OrderDTO>> getOrder(
            @PathVariable String orderId,
            HttpServletRequest request) {

        Optional<OrderDTO> orderOpt = orderService.fetchOrder(orderId);

        if (orderOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    ApiResponseDTO.error(
                            "Không tìm thấy đơn hàng",
                            HttpStatus.NOT_FOUND,
                            request.getRequestURI()
                    )
            );
        }

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy thông tin đơn hàng thành công",
                        orderOpt.get(),
                        HttpStatus.OK
                )
        );
    }

    @GetMapping("/{orderId}/tracking")
    @Operation(summary = "Tracking đơn hàng qua GoShip",
            description = "Lấy thông tin tracking realtime từ GoShip")
    public ResponseEntity<ApiResponseDTO<ShipmentResponse>> trackOrder(
            @PathVariable String orderId,
            HttpServletRequest request) {

        try {
            Optional<OrderDTO> orderOpt = orderService.fetchOrder(orderId);

            if (orderOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                        ApiResponseDTO.error(
                                "Không tìm thấy đơn hàng",
                                HttpStatus.NOT_FOUND,
                                request.getRequestURI()
                        )
                );
            }

            OrderDTO order = orderOpt.get();

            if (order.getGoshipShipmentId() == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                        ApiResponseDTO.error(
                                "Đơn hàng chưa có thông tin vận chuyển",
                                HttpStatus.BAD_REQUEST,
                                request.getRequestURI()
                        )
                );
            }

            // Lấy thông tin tracking từ GoShip
            ShipmentResponse shipment = goShipService.getShipment(order.getGoshipShipmentId());

            return ResponseEntity.ok(
                    ApiResponseDTO.success(
                            "Lấy thông tin tracking thành công",
                            shipment,
                            HttpStatus.OK
                    )
            );

        } catch (Exception e) {
            log.error("Error tracking order {}: {}", orderId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi lấy thông tin tracking: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }
}
