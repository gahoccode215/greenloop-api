package com.greenloop.order.command.controller;

import com.greenloop.order.dto.request.order.offline.POSCheckoutRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.order.offline.POSCheckoutResponse;
import com.greenloop.order.service.POSService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/pos")
@RequiredArgsConstructor
@Tag(name = "POS", description = "Point of Sale - Offline checkout at events")
public class POSController {

    private final POSService posService;

    @Operation(
            summary = "POS Checkout",
            description = "Staff checkout sản phẩm cho khách tại event offline"
    )
    @PostMapping("/checkout")
    public ResponseEntity<ApiResponseDTO<POSCheckoutResponse>> checkout(
            @Valid @RequestBody POSCheckoutRequest request) {

        POSCheckoutResponse response = posService.checkout(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Checkout thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }
}
