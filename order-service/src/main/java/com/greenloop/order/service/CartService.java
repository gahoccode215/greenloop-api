package com.greenloop.order.service;

import com.greenloop.order.dto.request.AddToCartRequest;
import com.greenloop.order.dto.request.EstimateShippingFeeRequest;
import com.greenloop.order.dto.response.CartResponse;
import com.greenloop.order.dto.response.ShippingEstimateResponse;

public interface CartService {
    ShippingEstimateResponse estimateShippingFee(Long customerId, EstimateShippingFeeRequest request);
    CartResponse getCart(Long customerId);
    CartResponse addToCart(Long customerId, AddToCartRequest request);
    CartResponse removeCartItem(Long customerId, Long cartItemId);
    void clearCart(Long customerId);
}
