package com.greenloop.order.client;

import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.request.*;
import com.greenloop.order.dto.response.ApiResponseDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
        name = "product-service",
        path = "/api/v1"
)
public interface ProductClient {

    @PostMapping("/internal/products/validate-for-offline-order")
    ApiResponseDTO<Void> validateProductsForOfflineOrder(
            @RequestBody ProductValidationRequest request);

    @GetMapping("/internal/products/detail/{id}")
    ApiResponseDTO<ProductDTO> getProductDetailById(@PathVariable("id") Long id);

    @PostMapping("/internal/products/reserve")
    ApiResponseDTO<Void> reserveProducts(@RequestBody ReserveProductsRequest request);

    @PostMapping("/internal/products/unreserve")
    ApiResponseDTO<Void> unreserveProducts(@RequestBody UnreserveProductsRequest request);

    @PostMapping("/internal/products/mark-sold")
    ApiResponseDTO<Void> markProductsAsSold(@RequestBody MarkProductsSoldRequest request);

    @PostMapping("/internal/products/mark-offline-sold")
    ApiResponseDTO<Void> markOfflineProductsAsSold(
            @RequestBody MarkOfflineProductsSoldRequest request);

    @PostMapping("/internal/products/update-status")
    ApiResponseDTO<Void> updateProductStatus(@RequestBody UpdateProductStatusRequest request);
}
