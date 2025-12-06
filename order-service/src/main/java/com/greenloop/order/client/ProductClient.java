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
        path = "/api/v1"
)
public interface ProductClient {

    @PostMapping("/internal/products/validate-for-offline-order")
    ApiResponseDTO<Void> validateProductsForOfflineOrder(
            @RequestBody ProductValidationRequest request);

    @GetMapping("/internal/products/detail/{id}")
    ApiResponseDTO<ProductDTO> getProductDetailById(@PathVariable("id") Long id);
}
