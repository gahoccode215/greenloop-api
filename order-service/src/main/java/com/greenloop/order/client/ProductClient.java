package com.greenloop.order.client;

import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.request.ProductValidationRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
        name = "product-service",
        path = "/api/v1/internal/products"
)
public interface ProductClient {

    @GetMapping("/{id}")
    ApiResponseDTO<ProductDTO> getProductById(@PathVariable("id") Long id);

    @PostMapping("/validate-for-offline-order")
    ApiResponseDTO<Void> validateProductsForOfflineOrder(
            @RequestBody ProductValidationRequest request);

    @GetMapping("/detail/{id}")
    ApiResponseDTO<ProductDTO> getProductDetailById(@PathVariable("id") Long id);
}
