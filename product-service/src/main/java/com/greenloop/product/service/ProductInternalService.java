package com.greenloop.product.service;

import com.greenloop.product.dto.response.ProductResponse;

import java.util.List;

public interface ProductInternalService {

    void validateProductsForOfflineOrder(Long eventId, List<Long> productIds);

    ProductResponse getProductById(Long productId);
}
