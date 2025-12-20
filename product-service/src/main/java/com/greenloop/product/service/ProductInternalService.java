package com.greenloop.product.service;

import com.greenloop.product.dto.request.*;
import com.greenloop.product.dto.response.ProductResponse;

import java.util.List;

public interface ProductInternalService {

    void validateProductsForOfflineOrder(Long eventId, List<Long> productIds);

    ProductResponse getProductById(Long productId);
    void reserveProducts(ReserveProductsRequest request);
    void unreserveProducts(UnreserveProductsRequest request);
    void markProductsAsSold(MarkProductsSoldRequest request);
    void updateProductStatus(UpdateProductStatusRequest request);
    void markOfflineProductsAsSold(MarkOfflineProductsSoldRequest request);
}
