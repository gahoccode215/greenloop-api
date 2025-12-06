package com.greenloop.product.controller;

import com.greenloop.product.dto.request.ProductValidationRequest;
import com.greenloop.product.dto.response.ApiResponseDTO;
import com.greenloop.product.dto.response.ProductResponse;
import com.greenloop.product.service.ProductInternalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/internal/products")
@RequiredArgsConstructor
@Slf4j
public class ProductInternalController {

    private final ProductInternalService productInternalService;

    @PostMapping("/validate-for-offline-order")
    public ResponseEntity<ApiResponseDTO<Void>> validateProductsForOfflineOrder(
            @RequestBody ProductValidationRequest request) {

        log.info("Validating products for offline order. Event: {}, Products: {}",
                request.getEventId(), request.getProductIds());

        productInternalService.validateProductsForOfflineOrder(
                request.getEventId(),
                request.getProductIds()
        );

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Sản phẩm hợp lệ cho đơn hàng offline",
                        null,
                        HttpStatus.OK
                )
        );
    }
    @GetMapping("/detail/{id}")
    public ResponseEntity<ApiResponseDTO<ProductResponse>> getProductDetailById(
            @PathVariable("id") Long id) {

        log.info("Internal API Detail: Getting product with ecoPointValue for id: {}", id);

        ProductResponse product = productInternalService.getProductById(id);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy chi tiết sản phẩm thành công",
                        product,
                        HttpStatus.OK
                )
        );
    }
}
