package com.greenloop.product.controller;

import com.greenloop.product.dto.feign.UnreserveProductsRequest;
import com.greenloop.product.dto.request.*;
import com.greenloop.product.dto.response.ApiResponseDTO;
import com.greenloop.product.dto.response.ProductResponse;
import com.greenloop.product.service.ProductInternalService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/internal/products")
@RequiredArgsConstructor
public class ProductInternalController {

    private final ProductInternalService productInternalService;

    @PostMapping("/mark-offline-sold")
    public ResponseEntity<ApiResponseDTO<Void>> markOfflineProductsAsSold(
            @RequestBody MarkOfflineProductsSoldRequest request) {
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
