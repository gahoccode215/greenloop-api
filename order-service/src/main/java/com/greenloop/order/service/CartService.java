package com.greenloop.order.service;

import com.greenloop.order.dto.request.AddToCartRequest;
import com.greenloop.order.dto.response.CartResponse;

public interface CartService {
    CartResponse getCart(Long customerId);
    CartResponse addToCart(Long customerId, AddToCartRequest request);
    CartResponse removeCartItem(Long customerId, Long cartItemId);
    void clearCart(Long customerId);
}
