package com.greenloop.order.query.controller;

import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.dto.response.ApiResponseDTO;
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

}
