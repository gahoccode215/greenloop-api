package com.greenloop.order.ghn.controller;

import com.greenloop.order.dto.ApiResponseDTO;
import com.greenloop.order.ghn.dto.response.ShippingOrderResponse;
import com.greenloop.order.ghn.service.GHNService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequestMapping("/api/v1/orders/ghn")
@Tag(name = "GHN")
@RequiredArgsConstructor
public class GHNController {

    private final GHNService ghnService;

    @PostMapping("/{orderId}/shipping")
    public ResponseEntity<ApiResponseDTO<ShippingOrderResponse>> createShipping(
            @PathVariable String orderId) {
        ShippingOrderResponse response = ghnService.createShippingOrder(orderId);
        return ResponseEntity.ok(ApiResponseDTO.success(
                "Tạo vận đơn thành công",
                response,
                HttpStatus.OK
        ));
    }

}
