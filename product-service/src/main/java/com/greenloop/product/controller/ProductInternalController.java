package com.greenloop.product.controller;

import com.greenloop.product.dto.request.*;
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

    @PostMapping("/mark-offline-sold")
    public ResponseEntity<ApiResponseDTO<Void>> markOfflineProductsAsSold(
            @RequestBody MarkOfflineProductsSoldRequest request) {

        log.info("Mark OFFLINE products as SOLD API called for order: {}, event: {}, products count: {}",
                request.getOrderId(), request.getEventId(), request.getProducts().size());

        productInternalService.markOfflineProductsAsSold(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Đã đánh dấu sản phẩm offline là SOLD và mapping là SOLD_OUT thành công",
                        null,
                        HttpStatus.OK
                )
        );
    }

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

    @PostMapping("/reserve")
    public ResponseEntity<ApiResponseDTO<Void>> reserveProducts(
            @RequestBody ReserveProductsRequest request) {

        log.info("Reserve products API called for order: {}, products count: {}",
                request.getOrderId(), request.getProducts().size());

        productInternalService.reserveProducts(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Đã reserve sản phẩm thành công",
                        null,
                        HttpStatus.OK
                )
        );
    }

    @PostMapping("/unreserve")
    public ResponseEntity<ApiResponseDTO<Void>> unreserveProducts(
            @RequestBody UnreserveProductsRequest request) {

        log.info("Unreserve products API called for order: {}, products count: {}",
                request.getOrderId(), request.getProducts().size());

        productInternalService.unreserveProducts(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Đã unreserve sản phẩm thành công",
                        null,
                        HttpStatus.OK
                )
        );
    }

    @PostMapping("/mark-sold")
    public ResponseEntity<ApiResponseDTO<Void>> markProductsAsSold(
            @RequestBody MarkProductsSoldRequest request) {

        log.info("Mark products as SOLD API called for order: {}, products count: {}",
                request.getOrderId(), request.getProducts().size());

        productInternalService.markProductsAsSold(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Đã đánh dấu sản phẩm là SOLD thành công",
                        null,
                        HttpStatus.OK
                )
        );
    }

    @PostMapping("/update-status")
    public ResponseEntity<ApiResponseDTO<Void>> updateProductStatus(
            @RequestBody UpdateProductStatusRequest request) {

        log.info("Update product status API called for order: {}, products count: {}",
                request.getOrderCode(), request.getProductUpdates().size());

        productInternalService.updateProductStatus(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Cập nhật trạng thái sản phẩm thành công",
                        null,
                        HttpStatus.OK
                )
        );
    }
}
