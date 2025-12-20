package com.greenloop.order.controller;

import com.greenloop.order.dto.request.DirectCheckoutRequest;
import com.greenloop.order.dto.request.DirectShippingEstimateRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.CheckoutResponse;
import com.greenloop.order.dto.response.ShippingEstimateResponse;
import com.greenloop.order.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Tag(name = "Direct Checkout", description = "Mua ngay sản phẩm không qua giỏ hàng")
public class DirectCheckoutController {

    private final OrderService orderService;

    @PostMapping("/direct-checkout")
    @PreAuthorize("hasRole('CUSTOMER')")
    @Operation(summary = "Mua ngay sản phẩm",
            description = "Checkout trực tiếp 1 sản phẩm, không tính các sản phẩm trong giỏ")
    public ResponseEntity<ApiResponseDTO<CheckoutResponse>> directCheckout(
            @RequestBody DirectCheckoutRequest request,
            Authentication authentication) {

        Long userId = Long.parseLong(authentication.getName());
        CheckoutResponse response = orderService.directCheckout(userId, request);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Direct checkout thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    @PostMapping("/direct-checkout/estimate-shipping")
    @PreAuthorize("hasRole('CUSTOMER')")
    @Operation(summary = "Ước tính phí ship cho mua ngay")
    public ResponseEntity<ApiResponseDTO<ShippingEstimateResponse>> estimateShipping(
            @RequestBody DirectShippingEstimateRequest request,
            Authentication authentication) {

        ShippingEstimateResponse response = orderService
                .estimateShippingForDirectCheckout(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Tính phí ship thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }
}
