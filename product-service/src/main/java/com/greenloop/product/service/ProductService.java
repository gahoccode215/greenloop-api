package com.greenloop.product.service;

import com.greenloop.product.dto.response.PageResponseDTO;
import com.greenloop.product.dto.response.ProductResponse;
import org.springframework.data.domain.Pageable;

public interface ProductService {

    PageResponseDTO<ProductResponse> getProducts(
            String search,
            String status,
            String type,
            Long categoryId,
            Pageable pageable
    );

    ProductResponse getProductDetail(Long id);
    void updateProductStatus(Long productId, String newStatus);
}
