package com.greenloop.order.client;

import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.response.ApiResponseDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(
        name = "product-service",
        path = "/api/v1/products"
)
public interface ProductClient {

    @GetMapping("/{id}")
    ApiResponseDTO<ProductDTO> getProductById(@PathVariable("id") Long id);
}
